#!/usr/bin/env python3
"""
ParsingPeas Parser
Parses linpeas/winpeas output and generates interactive HTML reports
"""

import os
import re
from datetime import datetime
from html import escape


def strip_ansi_codes(text):
    """Remove ANSI color codes from text"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def convert_ansi_to_html(text):
    """
    Convert ANSI codes to HTML for terminal-style display
    This creates actual colored text, not visible codes
    """
    # Map ANSI codes to CSS colors
    replacements = [
        (r'\x1B\[1;31m', '<span style="color:#ff5555;font-weight:bold">'),  # Bold Red
        (r'\x1B\[1;32m', '<span style="color:#50fa7b;font-weight:bold">'),  # Bold Green
        (r'\x1B\[1;33m', '<span style="color:#f1fa8c;font-weight:bold">'),  # Bold Yellow
        (r'\x1B\[1;34m', '<span style="color:#8be9fd;font-weight:bold">'),  # Bold Blue
        (r'\x1B\[1;35m', '<span style="color:#ff79c6;font-weight:bold">'),  # Bold Magenta
        (r'\x1B\[1;36m', '<span style="color:#8be9fd;font-weight:bold">'),  # Bold Cyan
        (r'\x1B\[31m', '<span style="color:#ff5555">'),  # Red
        (r'\x1B\[32m', '<span style="color:#50fa7b">'),  # Green
        (r'\x1B\[33m', '<span style="color:#f1fa8c">'),  # Yellow
        (r'\x1B\[34m', '<span style="color:#8be9fd">'),  # Blue
        (r'\x1B\[35m', '<span style="color:#ff79c6">'),  # Magenta
        (r'\x1B\[36m', '<span style="color:#8be9fd">'),  # Cyan
        (r'\x1B\[37m', '<span style="color:#f8f8f2">'),  # White
        (r'\x1B\[1m', '<span style="font-weight:bold">'),  # Bold
        (r'\x1B\[0m', '</span>'),  # Reset
        (r'\x1B\[m', '</span>'),  # Reset alternative
    ]
    
    result = escape(text)  # Escape HTML first
    
    # Apply ANSI to HTML conversions
    for pattern, replacement in replacements:
        result = re.sub(pattern, replacement, result)
    
    # Clean up any remaining ANSI codes
    result = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', result)
    
    return result


def parse_linpeas_sections(content):
    """
    Parse linpeas output using actual section markers
    Linpeas uses box-drawing characters for sections:
    - ╔═══════════╗ for main sections
    - [+] for subsections
    """
    # Work with clean content (no ANSI)
    clean_content = strip_ansi_codes(content)
    
    sections = {}
    current_section = "System Information"
    current_content = []
    
    lines = clean_content.split('\n')
    
    for line in lines:
        # Detect main section headers (box-drawing characters)
        if re.search(r'[╔╗═]{3,}', line):
            # Save previous section
            if current_content:
                sections[current_section] = '\n'.join(current_content)
                current_content = []
            continue
        
        # Detect section titles (usually between box chars or with specific format)
        if re.search(r'╚[═─]+╝', line):
            continue
            
        # Main category lines (usually all caps or colored)
        if line.strip() and len(line.strip()) > 3:
            # Check if this looks like a section header
            stripped = line.strip()
            if (stripped.isupper() and len(stripped) < 100) or \
               stripped.startswith('[+]') or \
               (stripped.startswith('═') and '═' in stripped[1:]):
                # This is likely a new section
                if current_content:
                    sections[current_section] = '\n'.join(current_content)
                current_section = stripped.replace('[+]', '').strip()
                current_content = []
                continue
        
        # Regular content line
        current_content.append(line)
    
    # Save last section
    if current_content:
        sections[current_section] = '\n'.join(current_content)
    
    return sections


def extract_critical_findings(content):
    """
    Extract actual critical findings based on linpeas indicators
    """
    clean_content = strip_ansi_codes(content)
    findings = []
    seen = set()
    
    patterns = [
        # Linpeas specific confidence markers
        (r'.*RED/YELLOW.*99%.*', 'critical'),
        (r'.*RED/YELLOW.*95%.*', 'critical'),
        
        # CVE vulnerabilities
        (r'.*\[CVE-\d{4}-\d{4,}\].*', 'high'),
        
        # Privilege escalation indicators  
        (r'.*NOPASSWD.*', 'high'),
        (r'.*\(ALL\s*:\s*ALL\).*', 'high'),
        (r'.*password.*found.*', 'high'),
        
        # Writable critical files
        (r'.*writable.*/etc/passwd.*', 'critical'),
        (r'.*writable.*/etc/shadow.*', 'critical'),
        (r'.*writable.*\.service.*', 'medium'),
        (r'.*writable.*cron.*', 'medium'),
    ]
    
    for line in clean_content.split('\n'):
        line_clean = line.strip()
        
        # Skip empty, very short, or header lines
        if not line_clean or len(line_clean) < 15:
            continue
        if '═' in line_clean or '╔' in line_clean or '╗' in line_clean:
            continue
            
        # Check patterns
        for pattern, severity in patterns:
            if re.search(pattern, line_clean, re.IGNORECASE):
                if line_clean not in seen and len(line_clean) < 300:
                    findings.append({
                        'severity': severity,
                        'content': line_clean
                    })
                    seen.add(line_clean)
                break
    
    return findings[:50]


def generate_html_report(filepath, hostname, scan_type):
    """Generate interactive HTML report from scan output"""
    
    # Read raw content
    with open(filepath, 'r', errors='ignore') as f:
        raw_content = f.read()
    
    # Parse sections from clean content
    sections = parse_linpeas_sections(raw_content)
    findings = extract_critical_findings(raw_content)
    
    # For terminal view: convert ANSI to HTML colors (not escaped HTML)
    terminal_html = convert_ansi_to_html(raw_content)
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Generate TOC
    toc_items = ''.join([
        f'<li><a href="#section-{i}" onclick="scrollToSection({i}); return false;">{escape(title[:80])}</a></li>'
        for i, title in enumerate(sections.keys())
    ])
    
    # Generate sections HTML
    sections_html = ''
    for i, (title, content) in enumerate(sections.items()):
        sections_html += f'''
        <div class="section" id="section-{i}">
            <div class="section-title" onclick="toggleSection(this)">▶ {escape(title)}</div>
            <div class="section-content" style="display: none;">{escape(content)}</div>
        </div>
        '''
    
    # Generate findings HTML
    if findings:
        findings_html = ''.join([
            f'<div class="highlight-item {f["severity"]}">{escape(f["content"])}</div>'
            for f in findings
        ])
    else:
        findings_html = '<div class="no-findings">No high-priority findings detected.</div>'
    
    # Create complete HTML
    html = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ParsingPeas Report - {escape(hostname)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: \'Courier New\', monospace; background: #0a0e27; color: #00ff00; padding: 20px; }}
        
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 30px; border-radius: 10px; margin-bottom: 30px; border: 2px solid #00ff00;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; text-shadow: 0 0 10px #00ff00; }}
        .header .info {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px; margin-top: 20px;
        }}
        .info-item {{
            background: rgba(0, 255, 0, 0.1); padding: 10px; border-radius: 5px;
            border-left: 3px solid #00ff00;
        }}
        
        .view-toggle {{ display: flex; gap: 10px; margin-bottom: 20px; }}
        .view-btn {{
            padding: 12px 24px; background: #1a1a2e; border: 2px solid #00ff00;
            color: #00ff00; cursor: pointer; border-radius: 5px;
            font-family: \'Courier New\', monospace; font-size: 14px; transition: all 0.3s;
        }}
        .view-btn:hover {{ background: rgba(0, 255, 0, 0.1); }}
        .view-btn.active {{ background: #00ff00; color: #0a0e27; font-weight: bold; }}
        
        .view-content {{ display: none; }}
        .view-content.active {{ display: block; }}
        
        .toc {{
            background: #1a1a2e; padding: 20px; border-radius: 10px;
            margin-bottom: 30px; border: 2px solid #00ff00; max-height: 400px; overflow-y: auto;
        }}
        .toc h2 {{ margin-bottom: 15px; color: #00ff00; }}
        .toc ul {{ list-style: none; column-count: 2; column-gap: 20px; }}
        .toc li {{ margin: 5px 0; break-inside: avoid; }}
        .toc a {{
            color: #50fa7b; text-decoration: none; display: block;
            padding: 5px; border-radius: 3px; transition: all 0.2s;
        }}
        .toc a:hover {{ background: rgba(0, 255, 0, 0.1); padding-left: 10px; }}
        
        .highlights {{
            background: #1a1a2e; padding: 20px; border-radius: 10px;
            margin-bottom: 30px; border: 2px solid #ff6b6b;
        }}
        .highlights h2 {{ color: #ff6b6b; margin-bottom: 15px; }}
        .highlight-item {{
            padding: 10px; margin: 5px 0; border-radius: 5px;
            border-left: 4px solid; font-size: 13px;
        }}
        .critical {{ background: rgba(255, 0, 0, 0.2); border-left-color: #ff0000; }}
        .high {{ background: rgba(255, 107, 107, 0.2); border-left-color: #ff6b6b; }}
        .medium {{ background: rgba(255, 165, 0, 0.2); border-left-color: #ffa500; }}
        
        .search-box {{
            width: 100%; padding: 15px; background: #1a1a2e; border: 2px solid #00ff00;
            color: #00ff00; font-size: 16px; border-radius: 5px; margin-bottom: 20px;
        }}
        
        .section {{
            background: #1a1a2e; padding: 20px; margin-bottom: 20px;
            border-radius: 10px; border: 1px solid #333; scroll-margin-top: 20px;
        }}
        .section-title {{
            color: #00ff00; cursor: pointer; padding: 10px;
            background: rgba(0, 255, 0, 0.1); border-radius: 5px;
            margin-bottom: 10px; user-select: none;
        }}
        .section-title:hover {{ background: rgba(0, 255, 0, 0.2); }}
        .section-content {{
            white-space: pre-wrap; font-family: \'Courier New\', monospace;
            font-size: 13px; line-height: 1.5; padding: 15px;
            background: rgba(0, 0, 0, 0.3); border-radius: 5px;
            max-height: 600px; overflow-y: auto;
        }}
        
        .raw-output {{
            background: #1a1a2e; padding: 20px; border-radius: 10px;
            border: 2px solid #00ff00; white-space: pre-wrap;
            font-family: \'Courier New\', monospace; font-size: 12px; line-height: 1.4;
            max-height: 80vh; overflow-y: auto; color: #f8f8f2;
        }}
        
        .section-content::-webkit-scrollbar,
        .toc::-webkit-scrollbar,
        .raw-output::-webkit-scrollbar {{ width: 10px; }}
        .section-content::-webkit-scrollbar-track,
        .toc::-webkit-scrollbar-track,
        .raw-output::-webkit-scrollbar-track {{ background: #0a0e27; }}
        .section-content::-webkit-scrollbar-thumb,
        .toc::-webkit-scrollbar-thumb,
        .raw-output::-webkit-scrollbar-thumb {{
            background: #00ff00; border-radius: 5px;
        }}
        
        .no-findings {{ color: #888; font-style: italic; padding: 15px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🥒 ParsingPeas Report</h1>
        <div class="info">
            <div class="info-item"><strong>Hostname:</strong> {escape(hostname)}</div>
            <div class="info-item"><strong>Scan Type:</strong> {escape(scan_type)}</div>
            <div class="info-item"><strong>Generated:</strong> {timestamp}</div>
            <div class="info-item"><strong>Sections:</strong> {len(sections)}</div>
        </div>
    </div>
    
    <div class="view-toggle">
        <button class="view-btn active" onclick="switchView(\'parsed\')">📊 Parsed View</button>
        <button class="view-btn" onclick="switchView(\'raw\')">💻 Terminal View</button>
    </div>
    
    <!-- Parsed View -->
    <div id="parsed-view" class="view-content active">
        <div class="toc">
            <h2>📋 Table of Contents</h2>
            <ul>{toc_items}</ul>
        </div>
        
        <input type="text" class="search-box" id="searchBox" placeholder="🔍 Search parsed output..." />
        
        <div class="highlights">
            <h2>⚠️ Critical Findings ({len(findings)})</h2>
            {findings_html}
        </div>
        
        <div id="sections">{sections_html}</div>
    </div>
    
    <!-- Raw Terminal View -->
    <div id="raw-view" class="view-content">
        <input type="text" class="search-box" id="searchBoxRaw" placeholder="🔍 Search raw output..." />
        <div class="raw-output">{terminal_html}</div>
    </div>
    
    <script>
        function switchView(view) {{
            document.querySelectorAll('.view-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.view-content').forEach(content => content.classList.remove('active'));
            
            if (view === 'parsed') {{
                document.querySelectorAll('.view-btn')[0].classList.add('active');
                document.getElementById('parsed-view').classList.add('active');
            }} else {{
                document.querySelectorAll('.view-btn')[1].classList.add('active');
                document.getElementById('raw-view').classList.add('active');
            }}
        }}
        
        function toggleSection(element) {{
            const content = element.nextElementSibling;
            if (content.style.display === 'none') {{
                content.style.display = 'block';
                element.innerHTML = element.innerHTML.replace('▶', '▼');
            }} else {{
                content.style.display = 'none';
                element.innerHTML = element.innerHTML.replace('▼', '▶');
            }}
        }}
        
        function scrollToSection(index) {{
            const section = document.getElementById('section-' + index);
            section.scrollIntoView({{ behavior: 'smooth' }});
            const title = section.querySelector('.section-title');
            const content = section.querySelector('.section-content');
            if (content.style.display === 'none') toggleSection(title);
        }}
        
        document.getElementById('searchBox').addEventListener('input', function(e) {{
            const searchTerm = e.target.value.toLowerCase();
            document.querySelectorAll('.section').forEach(section => {{
                section.style.display = section.textContent.toLowerCase().includes(searchTerm) ? 'block' : 'none';
            }});
        }});
    </script>
</body>
</html>
    '''
    
    # Save report
    report_filename = f"report_{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    report_path = os.path.join('reports', report_filename)
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    return report_path


if __name__ == '__main__':
    print("ParsingPeas Parser - Test mode")
    import sys
    if len(sys.argv) > 1:
        generate_html_report(sys.argv[1], 'test', 'linpeas')
