#!/usr/bin/env python3
"""
ParsingPeas Parser
Parses linpeas/winpeas output and generates interactive HTML reports
"""

import os
import re
from datetime import datetime
from html import escape
from collections import OrderedDict


def strip_ansi_codes(text):
    """Remove ANSI color codes from text"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def convert_ansi_to_html_colors(text, for_terminal=True):
    """
    Convert ANSI codes to colored HTML
    for_terminal: True = terminal view formatting, False = parsed view formatting
    """
    lines = text.split('\n')
    result_lines = []
    
    for line in lines:
        # Check if this is a header line
        is_header = '\x1B[1;32m' in line
        has_box = bool(re.search(r'[\u2554\u2557\u2551\u255a\u255d\u2550]', line))
        
        processed = line
        
        # Map ANSI codes to HTML colors
        color_map = [
            (r'\x1B\[1;31m', '<span style="color:#ff6b6b;font-weight:bold">'),  # Bold Red
            (r'\x1B\[1;32m', '<span style="color:#50fa7b;font-weight:bold">'),  # Bold Green
            (r'\x1B\[1;33m', '<span style="color:#f1fa8c;font-weight:bold">'),  # Bold Yellow
            (r'\x1B\[1;34m', '<span style="color:#8be9fd;font-weight:bold">'),  # Bold Blue
            (r'\x1B\[1;35m', '<span style="color:#ff79c6;font-weight:bold">'),  # Bold Magenta
            (r'\x1B\[1;36m', '<span style="color:#8be9fd;font-weight:bold">'),  # Bold Cyan
            (r'\x1B\[31m', '<span style="color:#ff5555">'),
            (r'\x1B\[32m', '<span style="color:#50fa7b">'),
            (r'\x1B\[33m', '<span style="color:#f1fa8c">'),
            (r'\x1B\[34m', '<span style="color:#8be9fd">'),
            (r'\x1B\[35m', '<span style="color:#ff79c6">'),
            (r'\x1B\[36m', '<span style="color:#8be9fd">'),
            (r'\x1B\[37m', '<span style="color:#f8f8f2">'),
            (r'\x1B\[1m', '<span style="font-weight:bold">'),
            (r'\x1B\[0m', '</span>'),
            (r'\x1B\[m', '</span>'),
        ]
        
        # Apply color conversions
        for pattern, replacement in color_map:
            processed = re.sub(pattern, replacement, processed)
        
        # Remove remaining ANSI codes
        processed = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', processed)
        
        # Escape HTML but preserve spans
        processed = processed.replace('&', '&amp;')
        processed = processed.replace('<', '&lt;').replace('>', '&gt;')
        processed = processed.replace('&lt;span', '<span').replace('&lt;/span&gt;', '</span>')
        processed = re.sub(r'style=&quot;([^&]+?)&quot;&gt;', r'style="\1">', processed)
        
        # Format based on view type
        if for_terminal:
            # Terminal view: use divs with header highlighting
            if is_header and has_box:
                processed = f'<div class="term-header">{processed}</div>'
            else:
                processed = f'{processed}<br>'
        # Parsed view: just keep the spans, wrap in div for spacing
        
        result_lines.append(processed)
    
    return '\n'.join(result_lines)


def categorize_sections(sections):
    """
    Organize sections into categories based on linpeas structure
    """
    categories = OrderedDict()
    
    # Linpeas main category keywords
    category_keywords = [
        ('System Information', ['OS', 'Hostname', 'User & Groups', 'Sudo version', 'PATH', 'Date', 'System stats']),
        ('Container', ['Container', 'Docker', 'Kubernetes', 'LXC']),
        ('Cloud/VM', ['Cloud', 'AWS', 'Azure', 'GCP', 'VM', 'Hypervisor']),
        ('Processes & Cron', ['Processes', 'Binary processes', 'Cron', 'Systemd', 'Timers', 'Services']),
        ('Network Information', ['Network', 'Interfaces', 'Active Ports', 'Listening', 'Routes', 'Hosts']),
        ('Users & Groups', ['Users', 'Groups', 'IDs with shell', 'Password Policy', 'Last', 'Login']),
        ('Software Information', ['Software', 'Useful software', 'Installed', 'Compilers']),
        ('Interesting Files', ['SUID', 'Writable', 'Capabilities', 'Files', 'Backup', 'Logs', 'Web', 'ssh', 'Credentials']),
        ('API Keys & Secrets', ['API', 'password', 'credential', 'token', 'secret', 'Generic API', 'Searching']),
        ('Exploits & CVEs', ['CVE', 'Exploit', 'Vulnerable', 'Sudo', 'pkexec', 'Polkit']),
    ]
    
    for title in sections.keys():
        matched = False
        for cat_name, keywords in category_keywords:
            if any(keyword.lower() in title.lower() for keyword in keywords):
                if cat_name not in categories:
                    categories[cat_name] = []
                categories[cat_name].append(title)
                matched = True
                break
        
        if not matched:
            if "Other" not in categories:
                categories["Other"] = []
            categories["Other"].append(title)
    
    return categories


def parse_linpeas_by_ansi_colors(content):
    """
    Parse linpeas by detecting lines with BOLD GREEN (1;32m) color code
    """
    lines = content.split('\n')
    sections = OrderedDict()
    current_section = None
    current_content = []
    header_count = 0
    
    for line in lines:
        has_bold_green = '\x1B[1;32m' in line
        has_box = bool(re.search(r'[\u2554\u2557\u2551\u255a\u255d\u2550]', line))
        clean_line = strip_ansi_codes(line).strip()
        
        # Header detection
        if has_bold_green and has_box:
            if current_section and current_content:
                sections[current_section] = '\n'.join(current_content)
            
            # Extract title
            title = clean_line
            for char in '\u2554\u2557\u255a\u255d\u2550\u2551\u2500\u2502\u250c\u2510\u2514\u2518\u252c\u2534\u251c\u2524\u253c':
                title = title.replace(char, '')
            title = title.strip()
            
            if title and len(title) > 2:
                current_section = title
                current_content = []
                header_count += 1
                print(f"  [{header_count}] {title[:70]}")
                continue
        
        # Skip decoration lines
        if clean_line and all(c in '\u2554\u2557\u255a\u255d\u2550\u2551\u2500\u2502\u250c\u2510\u2514\u2518\u252c\u2534\u251c\u2524\u253c ' for c in clean_line):
            continue
        
        if current_section:
            current_content.append(line)
    
    if current_section and current_content:
        sections[current_section] = '\n'.join(current_content)
    
    print(f"\n  Total sections: {len(sections)}")
    return sections


def extract_critical_findings(content):
    """Extract critical findings"""
    clean = strip_ansi_codes(content)
    findings = []
    seen = set()
    
    patterns = [
        (r'RED/YELLOW.*99%', 'critical'),
        (r'RED/YELLOW.*95%', 'critical'),
        (r'\[CVE-\d{4}-\d{4,}\]', 'high'),
        (r'NOPASSWD', 'high'),
        (r'\(ALL\s*:\s*ALL\)', 'high'),
        (r'password.*found', 'high'),
        (r'writable.*/etc/(passwd|shadow)', 'critical'),
        (r'writable.*\.service', 'medium'),
        (r'writable.*cron', 'medium'),
    ]
    
    for line in clean.split('\n'):
        line = line.strip()
        if not line or len(line) < 15:
            continue
        if all(c in '\u2554\u2557\u255a\u255d\u2550\u2551\u2500\u2502\u250c\u2510\u2514\u2518\u252c\u2534\u251c\u2524\u253c ' for c in line):
            continue
        
        for pattern, severity in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                if line not in seen and len(line) < 300:
                    findings.append({'severity': severity, 'content': line})
                    seen.add(line)
                break
    
    return findings[:50]


def generate_html_report(filepath, hostname, scan_type):
    """Generate interactive HTML report"""
    
    print(f"\n\U0001f4ca Parsing {filepath}...\n")
    
    # Read file with proper encoding
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            raw_content = f.read()
    except:
        with open(filepath, 'rb') as f:
            raw_content = f.read().decode('utf-8', errors='ignore')
    
    print("\U0001f50d Detecting sections...")
    sections = parse_linpeas_by_ansi_colors(raw_content)
    
    print("\n\U0001f4c1 Organizing into categories...")
    categories = categorize_sections(sections)
    for cat_name, cat_sections in categories.items():
        print(f"  {cat_name}: {len(cat_sections)} sections")
    
    print("\n\u26a0\ufe0f  Extracting critical findings...")
    findings = extract_critical_findings(raw_content)
    print(f"  Found {len(findings)} critical findings")
    
    print("\n\U0001f4bb Generating views...")
    terminal_html = convert_ansi_to_html_colors(raw_content, for_terminal=True)
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Generate hierarchical TOC
    toc_html = ''
    section_idx = 0
    for cat_name, cat_sections in categories.items():
        cat_id = cat_name.replace(' ', '_').replace('/', '_')
        toc_html += f'<li class="cat"><div class="cat-title" onclick="toggleCat(\'{cat_id}\")">▶ {escape(cat_name)} ({len(cat_sections)})</div>'
        toc_html += f'<ul class="cat-sections" id="cat-{cat_id}">'
        for section_title in cat_sections:
            toc_html += f'<li><a href="#s{section_idx}" onclick="jump({section_idx}); return false;">{escape(section_title[:70])}</a></li>'
            section_idx += 1
        toc_html += '</ul></li>'
    
    # Generate sections WITH COLORS (use ANSI-to-HTML conversion)
    secs = ''.join([
        f'<div class="sec" id="s{i}">'
        f'<div class="st" onclick="tog(this)">\u25b6 {escape(t)}</div>'
        f'<div class="sc">{convert_ansi_to_html_colors(c, for_terminal=False)}</div>'
        f'</div>'
        for i, (t, c) in enumerate(sections.items())
    ])
    
    # Generate findings
    finds = ''.join([f'<div class="f {f["severity"]}">{escape(f["content"])}</div>' for f in findings]) if findings else '<div class="nf">No critical findings detected</div>'
    
    # JavaScript
    javascript = """
<script>
function sw(v) {
    document.querySelectorAll('.vb').forEach((b,i) => b.classList.toggle('active', i===v));
    document.querySelectorAll('.vc').forEach((c,i) => c.classList.toggle('active', i===v));
}

function tog(e) {
    let c = e.nextElementSibling;
    c.style.display = c.style.display === 'none' ? 'block' : 'none';
    e.innerHTML = c.style.display === 'none' ? '\u25b6 ' + e.innerHTML.slice(2) : '\u25bc ' + e.innerHTML.slice(2);
}

function toggleCat(id) {
    let cat = document.getElementById('cat-' + id);
    let title = event.target;
    cat.style.display = cat.style.display === 'none' ? 'block' : 'none';
    title.innerHTML = cat.style.display === 'none' ? '\u25b6 ' + title.innerHTML.slice(2) : '\u25bc ' + title.innerHTML.slice(2);
}

function jump(i) {
    let s = document.getElementById('s' + i);
    s.scrollIntoView({behavior: 'smooth'});
    let t = s.querySelector('.st');
    let c = s.querySelector('.sc');
    if (c.style.display === 'none') tog(t);
}

document.getElementById('sb').addEventListener('input', e => {
    let q = e.target.value.toLowerCase();
    document.querySelectorAll('.sec').forEach(s => {
        s.style.display = s.textContent.toLowerCase().includes(q) ? 'block' : 'none';
    });
});
</script>
    """
    
    # HTML template with FIXED TERMINAL COLORS
    html = f'''<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>ParsingPeas - {escape(hostname)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Courier New',monospace;background:#0a0e27;color:#e0e0e0;padding:20px}}
.hdr{{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:30px;border-radius:10px;margin-bottom:30px;border:2px solid #00ff00}}
.hdr h1{{font-size:2.5em;text-shadow:0 0 10px #00ff00;color:#00ff00}}
.info{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin-top:20px}}
.info div{{background:rgba(0,255,0,0.1);padding:10px;border-radius:5px;border-left:3px solid #00ff00;color:#ffffff}}
.vb{{padding:12px 24px;background:#1a1a2e;border:2px solid #00ff00;color:#00ff00;cursor:pointer;border-radius:5px;font:14px 'Courier New',monospace;margin-right:10px;transition:all .3s}}
.vb:hover{{background:rgba(0,255,0,0.1)}}
.vb.active{{background:#00ff00;color:#0a0e27;font-weight:bold}}
.vc{{display:none}}
.vc.active{{display:block}}
.toc{{background:#1a1a2e;padding:20px;border-radius:10px;margin:20px 0;border:2px solid #00ff00;max-height:600px;overflow-y:auto}}
.toc h2{{margin-bottom:15px;color:#00ff00}}
.toc ul{{list-style:none}}
.toc li{{margin:5px 0}}
.cat{{margin:10px 0}}
.cat-title{{color:#00ff00;font-weight:bold;padding:10px;background:rgba(0,255,0,0.1);border-radius:5px;cursor:pointer;user-select:none;transition:all .2s}}
.cat-title:hover{{background:rgba(0,255,0,0.2)}}
.cat-sections{{display:none;margin-left:20px;margin-top:5px}}
.cat-sections li{{margin:5px 0}}
.cat-sections a{{color:#50fa7b;text-decoration:none;display:block;padding:6px 10px;border-radius:3px;transition:all .2s;border-left:3px solid transparent}}
.cat-sections a:hover{{background:rgba(0,255,0,0.15);border-left-color:#00ff00;padding-left:14px}}
.sb{{width:100%;padding:15px;background:#1a1a2e;border:2px solid #00ff00;color:#00ff00;font-size:16px;border-radius:5px;margin-bottom:20px}}
.hl{{background:#1a1a2e;padding:20px;border-radius:10px;margin-bottom:30px;border:2px solid #ff6b6b}}
.hl h2{{color:#ff6b6b;margin-bottom:15px}}
.f{{padding:10px;margin:5px 0;border-radius:5px;border-left:4px solid;font-size:13px;color:#ffffff}}
.critical{{background:rgba(255,0,0,0.2);border-left-color:#f00}}
.high{{background:rgba(255,107,107,0.2);border-left-color:#ff6b6b}}
.medium{{background:rgba(255,165,0,0.2);border-left-color:#ffa500}}
.nf{{color:#888;font-style:italic;padding:15px}}
.sec{{background:#1a1a2e;padding:20px;margin-bottom:20px;border-radius:10px;border:1px solid #333;scroll-margin-top:20px}}
.st{{color:#00ff00;cursor:pointer;padding:10px;background:rgba(0,255,0,0.1);border-radius:5px;margin-bottom:10px;user-select:none}}
.st:hover{{background:rgba(0,255,0,0.2)}}
.sc{{white-space:pre-wrap;font:13px 'Courier New',monospace;line-height:1.6;padding:15px;background:rgba(0,0,0,0.3);border-radius:5px;max-height:600px;overflow-y:auto;display:none}}
.raw{{background:#0d1117;padding:20px;border-radius:10px;border:2px solid #30363d;font:12px 'Courier New',monospace;line-height:1.6;max-height:80vh;overflow-y:auto}}
.term-header{{background:rgba(80,250,123,0.08);padding:4px 8px;margin:6px 0;border-left:3px solid #50fa7b;border-radius:3px}}
.sc::-webkit-scrollbar,.toc::-webkit-scrollbar,.raw::-webkit-scrollbar{{width:10px}}
.sc::-webkit-scrollbar-track,.toc::-webkit-scrollbar-track,.raw::-webkit-scrollbar-track{{background:#0a0e27}}
.sc::-webkit-scrollbar-thumb,.toc::-webkit-scrollbar-thumb,.raw::-webkit-scrollbar-thumb{{background:#00ff00;border-radius:5px}}
</style></head><body>
<div class="hdr"><h1>\U0001f95a ParsingPeas Report</h1>
<div class="info"><div><strong>Hostname:</strong> {escape(hostname)}</div><div><strong>Type:</strong> {escape(scan_type)}</div><div><strong>Generated:</strong> {timestamp}</div><div><strong>Sections:</strong> {len(sections)}</div></div></div>
<div><button class="vb active" onclick="sw(0)">\U0001f4ca Parsed</button><button class="vb" onclick="sw(1)">\U0001f4bb Terminal</button></div>
<div id="p" class="vc active">
<div class="toc"><h2>\U0001f4cb Contents ({len(categories)} categories)</h2><ul>{toc_html}</ul></div>
<input type="text" class="sb" id="sb" placeholder="\U0001f50d Search..."/>
<div class="hl"><h2>\u26a0\ufe0f Critical Findings ({len(findings)})</h2>{finds}</div>
<div>{secs}</div>
</div>
<div id="r" class="vc"><input type="text" class="sb" placeholder="\U0001f50d Search raw..."/><div class="raw">{terminal_html}</div></div>
{javascript}
</body></html>'''
    
    os.makedirs('reports', exist_ok=True)
    report_filename = f"report_{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    report_path = os.path.join('reports', report_filename)
    
    with open(report_path, 'w', encoding='utf-8', errors='xmlcharrefreplace') as f:
        f.write(html)
    
    print(f"\n\u2705 Report generated: {report_path}\n")
    return report_path


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = generate_html_report(sys.argv[1], 'test', 'linpeas')
    else:
        print("Usage: python3 parser.py <linpeas_output_file>")
