#!/usr/bin/env python3
"""
ParsingPeas Parser
Parses linpeas/winpeas output and generates interactive HTML reports.
Rewritten for robustness and professional architecture.
"""

import os
import sys
import re
import json
import html
import argparse
from datetime import datetime
from pathlib import Path
from collections import OrderedDict

# --- Configuration ---
CHUNK_SIZE = 2000  # Lines per chunk for terminal view loading

class AnsiConverter:
    """
    Handles conversion of ANSI codes to HTML for report viewing.
    Uses a state-machine approach to ensure flat, valid HTML spans
    rather than deeply nested tags that can break browsers.
    """
    
    # Standard ANSI color codes to HTML hex values
    COLORS = {
        '30': '#000000', '31': '#ff5555', '32': '#50fa7b', '33': '#f1fa8c',
        '34': '#8be9fd', '35': '#ff79c6', '36': '#8be9fd', '37': '#f8f8f2',
        '90': '#6272a4', '91': '#ff6e6e', '92': '#69ff94', '93': '#ffffa5',
        '94': '#d6acff', '95': '#ff92df', '96': '#a4ffff', '97': '#ffffff',
    }

    def to_html(self, text):
        """
        Converts ANSI text to HTML spans with styling.
        Maintains a 'current style' state and emits flat <span> tags.
        """
        # 1. Sanitize the input text first
        # We process the text by splitting on ANSI codes
        # The regex captures the code so we can process it
        parts = re.split(r'\x1b\[([\d;]*)m', text)
        
        result = []
        current_style = {'color': None, 'bold': False, 'bg': None}
        
        # Helper to generate the opening span tag for current state
        def get_span_tag(style):
            css = []
            if style['color']: css.append(f"color:{style['color']}")
            if style['bold']: css.append("font-weight:bold")
            if style['bg']: css.append(f"background-color:{style['bg']}")
            
            if not css: return ""
            return f'<span style="{";".join(css)}">'

        # Process parts: [text, code, text, code, ...]
        # First part is always text (might be empty)
        if parts[0]:
            result.append(html.escape(parts[0]))
            
        # Iterate over code/text pairs
        # parts[1] is code, parts[2] is text, etc.
        for i in range(1, len(parts), 2):
            code_seq = parts[i]
            text_segment = parts[i+1]
            
            # Parse the ANSI code(s)
            codes = code_seq.split(';')
            for code in codes:
                if not code: code = '0' # Empty code \x1b[m means reset
                
                if code == '0':
                    current_style = {'color': None, 'bold': False, 'bg': None}
                elif code == '1':
                    current_style['bold'] = True
                elif code == '22':
                    current_style['bold'] = False
                elif code in self.COLORS:
                    current_style['color'] = self.COLORS[code]
                elif code == '39':
                    current_style['color'] = None # Default FG
                elif code == '49':
                    current_style['bg'] = None # Default BG
            
            if text_segment:
                span = get_span_tag(current_style)
                if span:
                    result.append(f"{span}{html.escape(text_segment)}</span>")
                else:
                    result.append(html.escape(text_segment))
                    
        return "".join(result)

    def strip(self, text):
        """Removes all ANSI codes for plain text analysis."""
        return re.sub(r'\x1b\[[\d;]*[a-zA-Z]', '', text)


class CategoryManager:
    """Manages the categorization of checks for both LinPEAS and WinPEAS."""
    
    # Define standardized categories and their keywords
    # Order matters: first match wins
    CATEGORIES = {
        "System Information": [
            "Basic information", "System Information", "OS Information", "Environment", 
            "Operative system", "Sudo version", "Hostname", "CPU", "Env"
        ],
        "Network Information": [
            "Network Information", "Interfaces", "Ports", "Listening", "Routes", "DNS", 
            "Hosts", "ARP", "Netstat", "Shares"
        ],
        "User Information": [
            "User Information", "Users & Groups", "Password Policy", "Logon Sessions", 
            "Clipboard", "LSA Secrets", "SAM", "Home folders", "Superusers", "Privileges"
        ],
        "Processes & Services": [
            "Processes Information", "Processes & Cron", "Services Information", 
            "Systemd", "Cron", "Scheduled Tasks", "Autoruns", "Running Processes", 
            "Binary processes"
        ],
        "Software & Containers": [
            "Software Information", "Installed Software", "Compiler", "Container", 
            "Docker", "Kubernetes", "Cloud", "AWS", "GCP", "Azure", "LXC", "Useful Software"
        ],
        "Files & Registry": [
            "File Information", "Interesting Files", "Registry Information", 
            "Writable Files", "Capabilities", "SUID", "SGID", "Permission", "Mounts"
        ],
        "Credentials & Secrets": [
            "Searching passwords", "Credentials", "API Keys", "Passwords", "Identities", 
            "SSH Keys", "History Files", "Browser", "Mails"
        ],
        "Vulnerabilities & Exploits": [
            "Exploits", "CVE", "Vulnerability", "Probes"
        ]
    }

    @classmethod
    def get_category(cls, section_title):
        """Returns the best-fit category for a given section title."""
        title_lower = section_title.lower()
        
        for category, keywords in cls.CATEGORIES.items():
            for keyword in keywords:
                if keyword.lower() in title_lower:
                    return category
                    
        return "Other Checks"


class PeasParser:
    """Parses Linpeas/Winpeas output into structured data."""
    
    def __init__(self, content):
        self.raw_content = content
        self.converter = AnsiConverter()
        self.clean_content = self.converter.strip(content)
        self.sections = OrderedDict() # Title -> Content
        self.categorized_sections = OrderedDict() # Category -> {Title -> Content}
        self.findings = []
        self.hostname = "unknown"

    def parse(self):
        """Main parsing execution flow."""
        self._extract_hostname()
        self._extract_sections()
        self._organize_categories()
        self._extract_findings()

    def _extract_hostname(self):
        """Extracts the hostname from standard PEAS patterns."""
        match = re.search(r'Hostname:\s*([\w\-\.]+)', self.clean_content, re.IGNORECASE)
        if match:
            self.hostname = match.group(1).strip()
        elif "hostname" in self.clean_content.lower():
             for line in self.clean_content.splitlines():
                 if line.lower().startswith("hostname:"):
                     self.hostname = line.split(":", 1)[1].strip()
                     break

    def _extract_sections(self):
        """Splits content into raw sections based on headers."""
        lines = self.raw_content.splitlines()
        current_header = "General Information"
        buffer = []
        
        # Regex to identify headers (Green + Bold)
        header_ansi_pattern = '\x1b[1;32m' 
        
        for line in lines:
            clean_line = self.converter.strip(line).strip()
            
            is_header = False
            if header_ansi_pattern in line:
                 if any(c in line for c in '╔════'): # WinPEAS/LinPEAS box style
                     is_header = True
                 elif clean_line.startswith('[+]') or clean_line.startswith('[-]'):
                     if len(clean_line) < 80 and not clean_line.endswith(':'): 
                        is_header = True

            if is_header:
                if buffer:
                    # Save previous section
                    if current_header in self.sections:
                        self.sections[current_header] += "\n" + "\n".join(buffer)
                    else:
                        self.sections[current_header] = "\n".join(buffer)
                    buffer = []
                
                # Clean title
                title = clean_line.translate(str.maketrans('', '', '╔╗╚╝║═[]+-')).strip()
                if title:
                    current_header = title
                buffer.append(line)
            else:
                buffer.append(line)
        
        if buffer:
            if current_header in self.sections:
                self.sections[current_header] += "\n" + "\n".join(buffer)
            else:
                self.sections[current_header] = "\n".join(buffer)

    def _organize_categories(self):
        """Groups extracted sections into standard categories."""
        # Initialize standard categories in order
        for cat in CategoryManager.CATEGORIES.keys():
            self.categorized_sections[cat] = OrderedDict()
        self.categorized_sections["Other Checks"] = OrderedDict()

        for title, content in self.sections.items():
            category = CategoryManager.get_category(title)
            self.categorized_sections[category][title] = content

    def _extract_findings(self):
        """Identifies critical findings based on PEAS color coding."""
        for line in self.raw_content.splitlines():
            # Red/Yellow = Critical
            if '1;31;103m' in line or '1;37;41m' in line: 
                clean = self.converter.strip(line).strip()
                if clean and len(clean) < 300: 
                    self.findings.append({'level': 'critical', 'text': clean})
            
            # Red = High
            elif '1;31m' in line: 
                clean = self.converter.strip(line).strip()
                if clean and len(clean) < 300 and "Scan" not in clean:
                    self.findings.append({'level': 'high', 'text': clean})


class ReportGenerator:
    """Generates the final HTML and JSON artifacts."""
    
    def __init__(self, parser, output_dir):
        self.parser = parser
        self.output_dir = Path(output_dir)
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
    def generate(self):
        terminal_json_name = f"terminal_{self.parser.hostname}_{self.timestamp}.json"
        self._save_terminal_data(terminal_json_name)
        
        html_content = self._build_html(terminal_json_name)
        
        report_name = f"report_{self.parser.hostname}_{self.timestamp}.html"
        with open(self.output_dir / report_name, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        return report_name

    def _save_terminal_data(self, filename):
        lines = self.parser.raw_content.splitlines()
        converted_lines = [self.parser.converter.to_html(line) for line in lines]
        chunks = ['\n'.join(converted_lines[i:i+CHUNK_SIZE]) for i in range(0, len(converted_lines), CHUNK_SIZE)]
        
        data = {
            "meta": {
                "hostname": self.parser.hostname,
                "lines": len(lines), 
                "chunks": len(chunks),
                "generated": self.timestamp
            },
            "chunks": chunks
        }
        
        with open(self.output_dir / filename, 'w', encoding='utf-8') as f:
            json.dump(data, f)

    def _build_html(self, json_file):
        toc_html = []
        content_html = []
        converter = AnsiConverter()
        
        idx = 0
        
        # Iterate through categories
        for category_name, sections in self.parser.categorized_sections.items():
            if not sections: continue
            
            # Add Category Header to TOC
            toc_html.append(f'<li class="toc-category">{html.escape(category_name)}</li>')
            
            # Add Sections
            for title, content in sections.items():
                if not content.strip(): continue
                
                safe_title = html.escape(title)
                toc_html.append(f'<li class="toc-item"><a href="#s{idx}">{safe_title}</a></li>')
                
                colored_content = converter.to_html(content)
                content_html.append(f'''
                    <section id="s{idx}" class="report-section">
                        <div class="section-header">
                            <span class="section-category">{category_name}</span>
                            <h3>{safe_title}</h3>
                        </div>
                        <pre class="content">{colored_content}</pre>
                    </section>
                ''')
                idx += 1

        findings_html = []
        if not self.parser.findings:
             findings_html.append('<div class="finding">No critical findings automatically detected.</div>')
        else:
            for f in self.parser.findings:
                findings_html.append(f'<div class="finding {f["level"]}">{html.escape(f["text"])}</div>')

        return HTML_TEMPLATE.format(
            hostname=self.parser.hostname,
            timestamp=self.timestamp,
            toc='\n'.join(toc_html),
            findings='\n'.join(findings_html),
            content='\n'.join(content_html),
            json_file=json_file
        )

# --- HTML Template ---
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ParsingPeas: {hostname}</title>
    <style>
        :root {{ --bg: #0f0f12; --text: #e0e0e0; --accent: #00ff00; --panel: #1a1a1f; --border: #333; }}
        body {{ background: var(--bg); color: var(--text); font-family: 'Consolas', 'Monaco', monospace; margin: 0; display: flex; height: 100vh; overflow: hidden; }}
        
        aside {{ width: 300px; background: var(--panel); border-right: 1px solid var(--border); display: flex; flex-direction: column; flex-shrink: 0; }}
        .brand {{ padding: 20px; font-size: 1.4em; color: var(--accent); font-weight: bold; border-bottom: 1px solid var(--border); letter-spacing: 1px; }}
        nav {{ flex: 1; overflow-y: auto; padding: 10px; scrollbar-width: thin; }}
        nav ul {{ list-style: none; padding: 0; margin: 0; }}
        
        /* TOC Categories */
        .toc-category {{ color: #fff; font-weight: bold; margin-top: 15px; margin-bottom: 5px; padding: 5px 12px; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #333; opacity: 0.7; }}
        .toc-item a {{ display: block; padding: 8px 12px 8px 20px; color: #888; text-decoration: none; border-radius: 4px; transition: 0.2s; font-size: 0.9em; border-left: 2px solid transparent; }}
        .toc-item a:hover {{ color: white; background: #25252b; }}
        .toc-item a.active {{ color: var(--accent); background: rgba(0,255,0,0.05); border-left-color: var(--accent); }}
        
        main {{ flex: 1; display: flex; flex-direction: column; overflow: hidden; position: relative; }}
        header {{ padding: 15px 30px; background: var(--panel); border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.2); }}
        
        .tabs {{ display: flex; gap: 10px; }}
        .tabs button {{ background: transparent; border: none; color: #888; padding: 8px 16px; cursor: pointer; font-family: inherit; font-size: 1em; border-radius: 4px; transition: 0.2s; font-weight: bold; }}
        .tabs button:hover {{ color: white; background: rgba(255,255,255,0.05); }}
        .tabs button.active {{ color: var(--bg); background: var(--accent); }}
        
        .meta-info {{ font-size: 0.85em; color: #666; }}
        
        .view {{ display: none; flex: 1; overflow-y: auto; padding: 30px; scroll-behavior: smooth; position: relative; }}
        .view.active {{ display: block; }}
        
        .report-section {{ margin-bottom: 40px; background: var(--panel); padding: 20px; border-radius: 8px; border: 1px solid var(--border); }}
        .section-header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 15px; margin-bottom: 15px; }}
        .section-header h3 {{ color: var(--accent); margin: 0; font-size: 1.2em; }}
        .section-category {{ font-size: 0.75em; background: #333; padding: 4px 8px; border-radius: 4px; color: #ccc; }}
        
        pre.content {{ white-space: pre-wrap; word-wrap: break-word; margin: 0; font-size: 0.9em; line-height: 1.5; color: #d0d0d0; }}
        
        #findings {{ margin-bottom: 30px; display: grid; gap: 10px; }}
        .finding {{ padding: 12px 15px; border-radius: 6px; background: #25252b; border-left: 4px solid #888; font-size: 0.9em; }}
        .finding.critical {{ border-left-color: #ff5555; background: rgba(255, 85, 85, 0.08); color: #ffcccc; }}
        .finding.high {{ border-left-color: #ffb86c; background: rgba(255, 184, 108, 0.08); color: #ffe6cc; }}
        
        #terminal-view {{ background: #000; color: #ccc; padding: 20px; font-family: 'Consolas', monospace; }}
        #term-content {{ font-size: 0.85em; line-height: 1.2; white-space: pre-wrap; word-break: break-all; }}
        
        #loading {{ position: absolute; bottom: 30px; right: 30px; background: var(--accent); color: var(--bg); padding: 8px 16px; border-radius: 4px; font-weight: bold; display: none; box-shadow: 0 4px 12px rgba(0,255,0,0.3); animation: pulse 1.5s infinite; }}
        @keyframes pulse {{ 0% {{ opacity: 0.8; }} 50% {{ opacity: 1; transform: scale(1.05); }} 100% {{ opacity: 0.8; }} }}
        
        ::-webkit-scrollbar {{ width: 10px; }}
        ::-webkit-scrollbar-track {{ background: var(--bg); }}
        ::-webkit-scrollbar-thumb {{ background: #333; border-radius: 5px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: #444; }}
    </style>
</head>
<body>
    <aside>
        <div class="brand">ParsingPeas</div>
        <nav>
            <ul>
                {toc}
            </ul>
        </nav>
    </aside>
    
    <main>
        <header>
            <div class="tabs">
                <button class="active" onclick="switchView('report')">Parsed Report</button>
                <button onclick="switchView('terminal')">Terminal Output</button>
            </div>
            <div class="meta-info">
                <span>Host: <strong>{hostname}</strong></span> | 
                <span>Generated: {timestamp}</span>
            </div>
        </header>
        
        <div id="report-view" class="view active">
            <div id="findings">
                <h3 style="color: #fff; margin-bottom: 15px;">Critical Findings</h3>
                {findings}
            </div>
            {content}
        </div>
        
        <div id="terminal-view" class="view">
            <pre id="term-content"></pre>
        </div>
        
        <div id="loading">Loading data...</div>
    </main>

    <script>
        const TERMINAL_FILE = '{json_file}';
        let terminalLoaded = false;
        let chunks = [];
        let nextChunkIdx = 0;
        
        function switchView(viewName) {{
            document.querySelectorAll('.view').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tabs button').forEach(el => el.classList.remove('active'));
            document.getElementById(viewName + '-view').classList.add('active');
            
            const btns = document.querySelectorAll('.tabs button');
            if (viewName === 'report') btns[0].classList.add('active');
            else btns[1].classList.add('active');
            
            if (viewName === 'terminal' && !terminalLoaded) {{
                loadTerminal();
            }}
        }}
        
        async function loadTerminal() {{
            const loader = document.getElementById('loading');
            loader.style.display = 'block';
            
            try {{
                const res = await fetch(TERMINAL_FILE);
                if (!res.ok) throw new Error("HTTP " + res.status);
                
                const data = await res.json();
                chunks = data.chunks;
                terminalLoaded = true;
                renderNextChunk();
                
            }} catch (e) {{
                document.getElementById('term-content').innerText = "Failed to load terminal data: " + e + "\\n\\nEnsure you are opening this via a web server.";
            }} finally {{
                loader.style.display = 'none';
            }}
        }}
        
        function renderNextChunk() {{
            if (nextChunkIdx >= chunks.length) return;
            const pre = document.getElementById('term-content');
            pre.innerHTML += chunks[nextChunkIdx] + "\\n"; 
            nextChunkIdx++;
        }}
        
        const termView = document.getElementById('terminal-view');
        termView.addEventListener('scroll', (e) => {{
            const el = e.target;
            if (el.scrollHeight - el.scrollTop - el.clientHeight < 400) {{
                renderNextChunk();
            }}
        }});
    </script>
</body>
</html>
"""

def main():
    if len(sys.argv) < 2:
        print("Usage: parser.py <input_file>")
        sys.exit(1)
        
    input_file = sys.argv[1]
    
    if not os.path.exists(input_file):
        print(f"Error: File '{input_file}' not found")
        sys.exit(1)
        
    print(f"[*] Parsing {input_file}...")
    try:
        with open(input_file, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
            
        parser = PeasParser(content)
        parser.parse()
        
        print(f"    - Detected Hostname: {parser.hostname}")
        print(f"    - Extracted Sections: {len(parser.sections)}")
        print(f"    - Critical Findings: {len(parser.findings)}")
        
        output_dir = 'reports'
        os.makedirs(output_dir, exist_ok=True)
        
        generator = ReportGenerator(parser, output_dir)
        report_path = generator.generate()
        
        print(f"[+] Successfully generated report:")
        print(f"    - {os.path.join(output_dir, report_path)}")
        
    except Exception as e:
        print(f"[!] Critical Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
