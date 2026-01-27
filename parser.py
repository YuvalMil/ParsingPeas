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
    Uses a state-machine approach to ensure flat, valid HTML spans.
    """
    
    COLORS = {
        '30': '#000000', '31': '#ff5555', '32': '#50fa7b', '33': '#f1fa8c',
        '34': '#8be9fd', '35': '#ff79c6', '36': '#8be9fd', '37': '#f8f8f2',
        '90': '#6272a4', '91': '#ff6e6e', '92': '#69ff94', '93': '#ffffa5',
        '94': '#d6acff', '95': '#ff92df', '96': '#a4ffff', '97': '#ffffff',
    }

    def to_html(self, text):
        parts = re.split(r'\x1b\[([\d;]*)m', text)
        result = []
        current_style = {'color': None, 'bold': False, 'bg': None}
        
        def get_span_tag(style):
            css = []
            if style['color']: css.append(f"color:{style['color']}")
            if style['bold']: css.append("font-weight:bold")
            if style['bg']: css.append(f"background-color:{style['bg']}")
            if not css: return ""
            return f'<span style="{";".join(css)}">'

        if parts[0]:
            result.append(html.escape(parts[0]))
            
        for i in range(1, len(parts), 2):
            code_seq = parts[i]
            text_segment = parts[i+1]
            codes = code_seq.split(';')
            
            for code in codes:
                if not code: code = '0'
                if code == '0': current_style = {'color': None, 'bold': False, 'bg': None}
                elif code == '1': current_style['bold'] = True
                elif code == '22': current_style['bold'] = False
                elif code in self.COLORS: current_style['color'] = self.COLORS[code]
                elif code == '39': current_style['color'] = None
                elif code == '49': current_style['bg'] = None
                # Handle red background for crits (often 41 or 101)
                elif code == '41': current_style['bg'] = '#ff0000'
                elif code == '101': current_style['bg'] = '#ff0000' 
            
            if text_segment:
                span = get_span_tag(current_style)
                if span:
                    result.append(f"{span}{html.escape(text_segment)}</span>")
                else:
                    result.append(html.escape(text_segment))
                    
        return "".join(result)

    def strip(self, text):
        return re.sub(r'\x1b\[[\d;]*[a-zA-Z]', '', text)


class CategoryManager:
    """Manages the categorization of checks."""
    
    # 12 Granular Categories
    CATEGORIES = {
        "System Information": [
            "Basic information", "System Information", "OS Information", "Environment", 
            "Operative system", "Hostname", "Env", "Version"
        ],
        "Kernel & Hardware": [
            "Kernel", "Loaded modules", "PCI devices", "USB devices", 
            "Dmesg output", "System stats", "CPU", "Drivers", "Processor",
            "Virtual machine", "Module", "Signature enforcement"
        ],
        "Security & Defenses": [
            "AppArmor", "SELinux", "ASLR", "Grub configuration", "Auditd", 
            "Defender", "Firewall", "Protections", "Security"
        ],
        "Network Information": [
            "Network Information", "Interfaces", "Ports", "Listening", "Routes", 
            "DNS", "Hosts", "ARP", "Netstat", "Shares"
        ],
        "User Information": [
            "User Information", "Users & Groups", "Password Policy", "Logon Sessions", 
            "LSA Secrets", "SAM", "Home folders", "Superusers", "Privileges", 
            "Console", "Last logon", "Sessions", "Sudo version"
        ],
        "Processes, Cron & Services": [
            "Processes Information", "Processes & Cron", "Services Information", 
            "Systemd", "Cron", "Scheduled Tasks", "Autoruns", "Running Processes", 
            "Binary processes", "Timers", "Sockets"
        ],
        "Software & Containers": [
            "Software Information", "Installed Software", "Compiler", "Container", 
            "Docker", "Kubernetes", "LXC", "Useful Software"
        ],
        "Platform & Cloud": [
            "Cloud", "AWS", "GCP", "Azure", "EC2", "Metadata"
        ],
        "Storage & Mounts": [
            "Mount points", "Disk space", "LVM information", "Partitions", 
            "Drives", "NFS exports"
        ],
        "Files & Permissions": [
            "File Information", "Interesting Files", "Registry Information", 
            "Writable Files", "Capabilities", "SUID", "SGID", "Permission"
        ],
        "Credentials & Secrets": [
            "Searching passwords", "Credentials", "API Keys", "Passwords", "Identities", 
            "SSH Keys", "History Files", "Browser", "Mails", "GPG keys", "Keyring", "Clipboard"
        ],
        "Vulnerabilities & Exploits": [
            "Exploits", "CVE", "Vulnerability", "Probes", "Exploit Suggester"
        ]
    }

    @classmethod
    def get_category(cls, section_title):
        title_lower = section_title.lower()
        for category, keywords in cls.CATEGORIES.items():
            for keyword in keywords:
                if keyword.lower() in title_lower:
                    return category
        return "Other Checks"


class PeasParser:
    """Parses Linpeas/Winpeas output."""
    
    def __init__(self, content):
        self.raw_content = content
        self.converter = AnsiConverter()
        self.clean_content = self.converter.strip(content)
        self.sections = OrderedDict()
        self.categorized_sections = OrderedDict()
        self.findings = [] # Flattened list of findings
        self.section_findings = {} # Map section_id -> list of findings
        self.hostname = "unknown"
        self.section_ids = {}

    def parse(self):
        self._extract_hostname()
        self._extract_sections()
        self._organize_categories()
        self._extract_findings_contextual()

    def _extract_hostname(self):
        match = re.search(r'Hostname:\s*([\w\-\.]+)', self.clean_content, re.IGNORECASE)
        if match:
            self.hostname = match.group(1).strip()
        elif "hostname" in self.clean_content.lower():
             for line in self.clean_content.splitlines():
                 if line.lower().startswith("hostname:"):
                     self.hostname = line.split(":", 1)[1].strip()
                     break

    def _extract_sections(self):
        lines = self.raw_content.splitlines()
        current_header = "General Information"
        buffer = []
        header_ansi_pattern = '\x1b[1;32m' 
        
        for line in lines:
            clean_line = self.converter.strip(line).strip()
            is_header = False
            if header_ansi_pattern in line:
                 if any(c in line for c in '╔════'):
                     is_header = True
                 elif clean_line.startswith('[+]') or clean_line.startswith('[-]'):
                     if len(clean_line) < 80 and not clean_line.endswith(':'): 
                        is_header = True

            if is_header:
                if buffer:
                    if current_header in self.sections:
                        self.sections[current_header] += "\n" + "\n".join(buffer)
                    else:
                        self.sections[current_header] = "\n".join(buffer)
                    buffer = []
                
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
        for cat in CategoryManager.CATEGORIES.keys():
            self.categorized_sections[cat] = OrderedDict()
        self.categorized_sections["Other Checks"] = OrderedDict()

        idx = 0
        for title, content in self.sections.items():
            category = CategoryManager.get_category(title)
            self.categorized_sections[category][title] = content
            self.section_ids[title] = f"s{idx}"
            idx += 1

    def _extract_findings_contextual(self):
        """Identifies findings and groups them by section."""
        self.findings = []
        self.section_findings = {} # Reset
        
        for title, content in self.sections.items():
            lines = content.splitlines()
            sec_id = self.section_ids.get(title, "")
            current_section_findings = []
            
            for line in lines:
                found = False
                level = ""
                
                # Check raw ANSI for exact LinPEAS signatures
                # Red/Yellow = 1;31;103m OR 1;37;41m (Bold Red on Yellow OR Bold White on Red)
                # Actually LinPEAS uses 1;37;41m (White on Red) for LEGEND RED/YELLOW usually
                # But we check both combinations seen in the wild
                
                if '1;37;41m' in line or '1;31;103m' in line or ';41m' in line:
                    level = 'critical'
                    found = True
                elif '1;31m' in line: # Bold Red
                    clean = self.converter.strip(line).strip()
                    if "Scan" not in clean and "started" not in clean and len(clean) < 300:
                        level = 'high'
                        found = True
                
                if found:
                    clean_text = self.converter.strip(line).strip()
                    if clean_text:
                        finding_obj = {
                            'level': level,
                            'text': clean_text,
                            'section': title,
                            'section_id': sec_id
                        }
                        self.findings.append(finding_obj)
                        current_section_findings.append(finding_obj)
            
            if current_section_findings:
                self.section_findings[title] = current_section_findings


class ReportGenerator:
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
        
        # Build TOC with Accordions
        for category_name, sections in self.parser.categorized_sections.items():
            if not sections: continue
            
            toc_html.append(f'''
            <li class="category-group">
                <details open>
                    <summary>{html.escape(category_name)} <span class="count">{len(sections)}</span></summary>
                    <ul>
            ''')
            
            for title, content in sections.items():
                if not content.strip(): continue
                safe_title = html.escape(title)
                sec_id = self.parser.section_ids[title]
                
                # TOC Indicators
                indicator = ''
                if title in self.parser.section_findings:
                    findings = self.parser.section_findings[title]
                    has_critical = any(f['level'] == 'critical' for f in findings)
                    if has_critical:
                        indicator = '<span class="toc-finding-dot critical"></span>'
                    else:
                        indicator = '<span class="toc-finding-dot high"></span>'
                
                toc_html.append(f'<li><a href="#{sec_id}">{safe_title} {indicator}</a></li>')
                
                colored_content = converter.to_html(content)
                content_html.append(f'''
                    <section id="{sec_id}" class="report-section">
                        <div class="section-header">
                            <span class="section-category">{category_name}</span>
                            <h3>{safe_title}</h3>
                            <a href="#" class="top-link">↑ Top</a>
                        </div>
                        <pre class="content">{colored_content}</pre>
                    </section>
                ''')
            
            toc_html.append('</ul></details></li>')

        # Build Grouped Findings Panel
        findings_html = []
        if not self.parser.section_findings:
             findings_html.append('<div class="finding-card empty">No critical findings automatically detected.</div>')
        else:
            for title, findings_list in self.parser.section_findings.items():
                sec_id = self.parser.section_ids[title]
                crit_count = sum(1 for f in findings_list if f['level'] == 'critical')
                high_count = sum(1 for f in findings_list if f['level'] == 'high')
                
                card_class = "critical" if crit_count > 0 else "high"
                
                findings_html.append(f'''
                <div class="finding-card {card_class}" onclick="scrollToSection('{sec_id}')">
                    <div class="finding-header">
                        <span class="section-name">{html.escape(title)}</span>
                    </div>
                    <div class="finding-stats">
                        {f'<span class="badge critical">{crit_count} Critical</span>' if crit_count else ''}
                        {f'<span class="badge high">{high_count} High</span>' if high_count else ''}
                    </div>
                    <div class="finding-footer">
                        Click to view details &rarr;
                    </div>
                </div>
                ''')

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
    <title>ParsingPeas: {hostname}</title>
    <style>
        :root {{ 
            --bg: #0f0f12; 
            --text: #e0e0e0; 
            --accent: #00ff00; 
            --panel: #1a1a1f; 
            --border: #333; 
            /* Correct LinPEAS Colors */
            --critical-bg: #ff0000;
            --critical-fg: #ffff00;
            --critical-glow: rgba(255, 0, 0, 0.4);
            --high-fg: #ff4444;
        }}
        body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', 'Consolas', monospace; margin: 0; display: flex; height: 100vh; overflow: hidden; }}
        
        aside {{ width: 340px; background: var(--panel); border-right: 1px solid var(--border); display: flex; flex-direction: column; flex-shrink: 0; user-select: none; }}
        .brand {{ padding: 20px; font-size: 1.4em; color: var(--accent); font-weight: bold; border-bottom: 1px solid var(--border); letter-spacing: 1px; }}
        nav {{ flex: 1; overflow-y: auto; padding: 10px; }}
        nav ul {{ list-style: none; padding: 0; margin: 0; }}
        
        /* Sidebar Controls */
        .nav-controls {{ padding: 10px; display: flex; gap: 5px; border-bottom: 1px solid var(--border); }}
        .nav-btn {{ flex: 1; background: #25252b; color: #aaa; border: 1px solid #444; border-radius: 4px; padding: 4px; cursor: pointer; font-size: 0.8em; }}
        .nav-btn:hover {{ color: #fff; border-color: #666; }}

        details {{ margin-bottom: 5px; }}
        summary {{ cursor: pointer; padding: 10px; background: rgba(255,255,255,0.03); border-radius: 4px; font-weight: bold; font-size: 0.9em; list-style: none; display: flex; justify-content: space-between; align-items: center; transition: background 0.2s; }}
        summary:hover {{ background: rgba(255,255,255,0.08); color: #fff; }}
        summary::-webkit-details-marker {{ display: none; }}
        details[open] summary {{ color: var(--accent); }}
        
        details li a {{ display: flex; justify-content: space-between; align-items: center; padding: 8px 15px 8px 25px; color: #888; text-decoration: none; font-size: 0.85em; transition: 0.2s; border-left: 2px solid transparent; }}
        details li a:hover {{ color: white; background: rgba(255,255,255,0.05); }}
        
        /* Sidebar Dots */
        .toc-finding-dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-left: 8px; }}
        .toc-finding-dot.high {{ background: var(--high-fg); box-shadow: 0 0 5px var(--high-fg); }}
        /* Critical dot mimics red/yellow */
        .toc-finding-dot.critical {{ background: var(--critical-bg); border: 2px solid var(--critical-fg); box-shadow: 0 0 5px var(--critical-bg); width: 8px; height: 8px; }}
        
        .count {{ font-size: 0.8em; opacity: 0.5; font-weight: normal; background: #333; padding: 2px 6px; border-radius: 10px; }}
        
        main {{ flex: 1; display: flex; flex-direction: column; overflow: hidden; }}
        header {{ padding: 15px 30px; background: var(--panel); border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }}
        .tabs button {{ background: transparent; border: none; color: #888; padding: 8px 16px; cursor: pointer; font-size: 1em; border-radius: 4px; transition: 0.2s; font-weight: bold; }}
        .tabs button.active {{ color: var(--bg); background: var(--accent); }}
        .meta-info {{ font-size: 0.85em; color: #666; }}
        
        .view {{ display: none; flex: 1; overflow-y: auto; padding: 30px; scroll-behavior: smooth; }}
        .view.active {{ display: block; }}
        
        /* New Grouped Findings Grid */
        #findings-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 15px; margin-bottom: 40px; }}
        
        .finding-card {{ background: #25252b; border: 1px solid #444; border-radius: 8px; padding: 20px; cursor: pointer; transition: all 0.2s; display: flex; flex-direction: column; gap: 10px; }}
        .finding-card:hover {{ transform: translateY(-3px); border-color: #777; box-shadow: 0 5px 15px rgba(0,0,0,0.3); }}
        
        /* Correct LinPEAS Critical Styling */
        .finding-card.critical {{ border-top: 4px solid var(--critical-bg); box-shadow: 0 0 10px var(--critical-glow) inset; }}
        .finding-card.high {{ border-top: 4px solid var(--high-fg); }}
        
        .finding-header {{ font-weight: bold; font-size: 1.1em; color: #fff; margin-bottom: 5px; }}
        .finding-stats {{ display: flex; gap: 10px; }}
        
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8em; color: #000; }}
        /* Critical = Red Background + Yellow Text */
        .badge.critical {{ background: var(--critical-bg); color: var(--critical-fg); text-shadow: 1px 1px 0 #000; }}
        .badge.high {{ background: var(--high-fg); color: #000; }}
        
        .finding-footer {{ font-size: 0.8em; color: #666; margin-top: auto; text-align: right; }}
        
        .report-section {{ margin-bottom: 50px; scroll-margin-top: 20px; }}
        .section-header {{ display: flex; align-items: center; gap: 15px; margin-bottom: 15px; border-bottom: 1px solid #333; padding-bottom: 10px; }}
        .section-category {{ font-size: 0.7em; text-transform: uppercase; letter-spacing: 1px; color: #666; border: 1px solid #333; padding: 4px 8px; border-radius: 4px; }}
        .section-header h3 {{ color: var(--accent); margin: 0; font-size: 1.3em; }}
        .top-link {{ margin-left: auto; color: #666; text-decoration: none; font-size: 0.8em; }}
        
        pre.content {{ white-space: pre-wrap; font-family: 'Consolas', monospace; font-size: 0.9em; background: #15151a; padding: 20px; border-radius: 6px; border: 1px solid #2a2a2a; color: #ccc; }}
        
        #terminal-view {{ background: #000; padding: 20px; }}
        #term-content {{ font-family: 'Consolas', monospace; font-size: 13px; color: #ccc; }}
        #loading {{ position: fixed; bottom: 20px; right: 20px; background: var(--accent); color: #000; padding: 10px 20px; border-radius: 20px; font-weight: bold; display: none; }}
        
        ::-webkit-scrollbar {{ width: 8px; }}
        ::-webkit-scrollbar-track {{ background: #0f0f12; }}
        ::-webkit-scrollbar-thumb {{ background: #333; border-radius: 4px; }}
    </style>
</head>
<body>
    <aside>
        <div class="brand">ParsingPeas</div>
        <div class="nav-controls">
            <button class="nav-btn" onclick="expandAll(true)">+ Open All</button>
            <button class="nav-btn" onclick="expandAll(false)">- Close All</button>
        </div>
        <nav>
            <ul>
                {toc}
            </ul>
        </nav>
    </aside>
    
    <main>
        <header>
            <div class="tabs">
                <button class="active" onclick="switchView('report')">Report Summary</button>
                <button onclick="switchView('terminal')">Full Terminal Output</button>
            </div>
            <div class="meta-info">Host: <strong>{hostname}</strong> | {timestamp}</div>
        </header>
        
        <div id="report-view" class="view active">
            <h2 style="color:white; margin-top:0">Critical Findings</h2>
            <div id="findings-grid">
                {findings}
            </div>
            <hr style="border:0; border-top:1px solid #333; margin: 40px 0;">
            {content}
        </div>
        
        <div id="terminal-view" class="view">
            <pre id="term-content"></pre>
        </div>
        
        <div id="loading">Loading...</div>
    </main>

    <script>
        const TERMINAL_FILE = '{json_file}';
        let terminalLoaded = false;
        let chunks = [];
        let nextChunkIdx = 0;
        
        function expandAll(open) {{
            document.querySelectorAll('details').forEach(el => el.open = open);
        }}
        
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
        
        function scrollToSection(id) {{
            if (!id) return;
            const el = document.getElementById(id);
            if (el) {{
                el.scrollIntoView({{behavior: 'smooth', block: 'start'}});
                el.style.transition = 'background 0.5s';
                el.style.background = 'rgba(0, 255, 0, 0.1)';
                setTimeout(() => el.style.background = '', 1000);
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
                document.getElementById('term-content').innerText = "Load failed: " + e;
            }} finally {{
                loader.style.display = 'none';
            }}
        }}
        
        function renderNextChunk() {{
            if (nextChunkIdx >= chunks.length) return;
            document.getElementById('term-content').innerHTML += chunks[nextChunkIdx] + "\\n"; 
            nextChunkIdx++;
        }}
        
        document.getElementById('terminal-view').addEventListener('scroll', (e) => {{
            if (e.target.scrollHeight - e.target.scrollTop - e.target.clientHeight < 400) {{
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
        
        output_dir = 'reports'
        os.makedirs(output_dir, exist_ok=True)
        
        generator = ReportGenerator(parser, output_dir)
        report_path = generator.generate()
        
        print(f"[+] Report generated: {os.path.join(output_dir, report_path)}")
        
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
