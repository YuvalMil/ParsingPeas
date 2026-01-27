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


def convert_ansi_to_html_colors(text):
    """
    Convert ANSI codes to colored HTML
    This is ONLY for terminal view - generates clean colored text
    """
    # First escape HTML to prevent any tags from being interpreted
    result = text
    
    # Replace ANSI codes with HTML color spans (do this BEFORE escaping)
    color_map = [
        (r'\x1B\[1;31m', '<span style="color:#ff5555;font-weight:bold">'),
        (r'\x1B\[1;32m', '<span style="color:#50fa7b;font-weight:bold">'),
        (r'\x1B\[1;33m', '<span style="color:#f1fa8c;font-weight:bold">'),
        (r'\x1B\[1;34m', '<span style="color:#8be9fd;font-weight:bold">'),
        (r'\x1B\[1;35m', '<span style="color:#ff79c6;font-weight:bold">'),
        (r'\x1B\[1;36m', '<span style="color:#8be9fd;font-weight:bold">'),
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
    
    # Apply color replacements
    for pattern, replacement in color_map:
        result = re.sub(pattern, replacement, result)
    
    # Remove any remaining ANSI codes
    result = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', result)
    
    # NOW escape HTML special characters (but preserve our color spans)
    # This is tricky - we need to escape everything except our span tags
    result = result.replace('&', '&amp;')
    result = result.replace('<', '&lt;').replace('>', '&gt;')
    # Restore our span tags
    result = result.replace('&lt;span', '<span').replace('&lt;/span&gt;', '</span>')
    result = result.replace('style=&quot;', 'style="').replace('&quot;&gt;', '">')
    
    return result


def parse_linpeas_by_headers(content):
    """
    Parse linpeas using the distinctive box-drawing headers:
    ╔═══════════╗
    ║ Title     ║  
    ╚═══════════╝
    """
    clean_content = strip_ansi_codes(content)
    
    sections = {}
    lines = clean_content.split('\n')
    
    i = 0
    current_section = "Introduction"
    current_content = []
    
    while i < len(lines):
        line = lines[i]
        
        # Detect section header (╔═══...═══╗)
        if '╔' in line and '╗' in line and '═' in line:
            # Save previous section
            if current_content:
                sections[current_section] = '\n'.join(current_content)
                current_content = []
            
            # Next line should have the title (║ Title ║)
            if i + 1 < len(lines):
                title_line = lines[i + 1]
                if '║' in title_line:
                    # Extract title between ║ characters
                    title = title_line.split('║')[1].strip() if '║' in title_line else title_line.strip()
                    current_section = title
                    
                    # Skip the closing line (╚═══...═══╝) 
                    i += 2
                    continue
        
        # Also detect [+] subsection markers
        elif line.strip().startswith('[+]'):
            # Save previous section
            if current_content:
                sections[current_section] = '\n'.join(current_content)
                current_content = []
            
            current_section = line.strip()
        else:
            # Regular content line
            current_content.append(line)
        
        i += 1
    
    # Save last section
    if current_content:
        sections[current_section] = '\n'.join(current_content)
    
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
        (r'writable.*/etc/(passwd|shadow)', 'critical'),
        (r'writable.*\.service', 'medium'),
    ]
    
    for line in clean.split('\n'):
        line = line.strip()
        if not line or len(line) < 15:
            continue
        if '╔' in line or '╗' in line or '║' in line or '╚' in line or '╝' in line:
            continue
            
        for pattern, severity in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                if line not in seen and len(line) < 300:
                    findings.append({'severity': severity, 'content': line})
                    seen.add(line)
                break
    
    return findings[:50]


def generate_html_report(filepath, hostname, scan_type):
    """Generate HTML report"""
    
    with open(filepath, 'r', errors='ignore') as f:
        raw_content = f.read()
    
    # Parse sections
    sections = parse_linpeas_by_headers(raw_content)
    findings = extract_critical_findings(raw_content)
    
    # Generate terminal view HTML (with colors)
    terminal_html = convert_ansi_to_html_colors(raw_content)
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # TOC
    toc = ''.join([f'<li><a href="#s{i}" onclick="jump({i})">{escape(t[:70])}</a></li>' 
                   for i, t in enumerate(sections.keys())])
    
    # Sections
    secs = ''.join([f'<div class="sec" id="s{i}"><div class="st" onclick="tog(this)">▶ {escape(t)}</div><div class="sc">{escape(c)}</div></div>'
                    for i, (t, c) in enumerate(sections.items())])
    
    # Findings
    finds = ''.join([f'<div class="f {f["severity"]}">{escape(f["content"])}</div>' for f in findings]) if findings else '<div class="nf">No critical findings</div>'
    
    html = f'''<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>ParsingPeas - {escape(hostname)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Courier New',monospace;background:#0a0e27;color:#00ff00;padding:20px}}
.hdr{{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:30px;border-radius:10px;margin-bottom:30px;border:2px solid #00ff00}}
.hdr h1{{font-size:2.5em;text-shadow:0 0 10px #00ff00}}
.info{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin-top:20px}}
.info div{{background:rgba(0,255,0,0.1);padding:10px;border-radius:5px;border-left:3px solid #00ff00}}
.vb{{padding:12px 24px;background:#1a1a2e;border:2px solid #00ff00;color:#00ff00;cursor:pointer;border-radius:5px;font:14px 'Courier New',monospace;margin-right:10px;transition:all .3s}}
.vb:hover{{background:rgba(0,255,0,0.1)}}
.vb.active{{background:#00ff00;color:#0a0e27;font-weight:bold}}
.vc{{display:none}}
.vc.active{{display:block}}
.toc{{background:#1a1a2e;padding:20px;border-radius:10px;margin:20px 0;border:2px solid #00ff00;max-height:400px;overflow-y:auto}}
.toc h2{{margin-bottom:15px}}
.toc ul{{list-style:none;column-count:2;column-gap:20px}}
.toc li{{margin:5px 0}}
.toc a{{color:#50fa7b;text-decoration:none;display:block;padding:5px;border-radius:3px;transition:all .2s}}
.toc a:hover{{background:rgba(0,255,0,0.1);padding-left:10px}}
.sb{{width:100%;padding:15px;background:#1a1a2e;border:2px solid #00ff00;color:#00ff00;font-size:16px;border-radius:5px;margin-bottom:20px}}
.hl{{background:#1a1a2e;padding:20px;border-radius:10px;margin-bottom:30px;border:2px solid #ff6b6b}}
.hl h2{{color:#ff6b6b;margin-bottom:15px}}
.f{{padding:10px;margin:5px 0;border-radius:5px;border-left:4px solid;font-size:13px}}
.critical{{background:rgba(255,0,0,0.2);border-left-color:#f00}}
.high{{background:rgba(255,107,107,0.2);border-left-color:#ff6b6b}}
.medium{{background:rgba(255,165,0,0.2);border-left-color:#ffa500}}
.nf{{color:#888;font-style:italic;padding:15px}}
.sec{{background:#1a1a2e;padding:20px;margin-bottom:20px;border-radius:10px;border:1px solid #333;scroll-margin-top:20px}}
.st{{color:#00ff00;cursor:pointer;padding:10px;background:rgba(0,255,0,0.1);border-radius:5px;margin-bottom:10px;user-select:none}}
.st:hover{{background:rgba(0,255,0,0.2)}}
.sc{{white-space:pre-wrap;font:13px 'Courier New',monospace;line-height:1.5;padding:15px;background:rgba(0,0,0,0.3);border-radius:5px;max-height:600px;overflow-y:auto;display:none}}
.raw{{background:#1a1a2e;padding:20px;border-radius:10px;border:2px solid #00ff00;white-space:pre-wrap;font:12px 'Courier New',monospace;line-height:1.4;max-height:80vh;overflow-y:auto;color:#f8f8f2}}
.sc::-webkit-scrollbar,.toc::-webkit-scrollbar,.raw::-webkit-scrollbar{{width:10px}}
.sc::-webkit-scrollbar-track,.toc::-webkit-scrollbar-track,.raw::-webkit-scrollbar-track{{background:#0a0e27}}
.sc::-webkit-scrollbar-thumb,.toc::-webkit-scrollbar-thumb,.raw::-webkit-scrollbar-thumb{{background:#00ff00;border-radius:5px}}
</style></head><body>
<div class="hdr"><h1>🥒 ParsingPeas Report</h1>
<div class="info"><div><strong>Hostname:</strong> {escape(hostname)}</div><div><strong>Type:</strong> {escape(scan_type)}</div><div><strong>Generated:</strong> {timestamp}</div><div><strong>Sections:</strong> {len(sections)}</div></div></div>
<div><button class="vb active" onclick="sw(0)">📊 Parsed</button><button class="vb" onclick="sw(1)">💻 Terminal</button></div>
<div id="p" class="vc active">
<div class="toc"><h2>📋 Contents</h2><ul>{toc}</ul></div>
<input type="text" class="sb" id="sb" placeholder="🔍 Search..."/>
<div class="hl"><h2>⚠️ Critical Findings ({len(findings)})</h2>{finds}</div>
<div>{secs}</div>
</div>
<div id="r" class="vc"><input type="text" class="sb" placeholder="🔍 Search raw..."/><div class="raw">{terminal_html}</div></div>
<script>
function sw(v){{document.querySelectorAll('.vb').forEach((b,i)=>{{b.classList.toggle('active',i===v)}});document.querySelectorAll('.vc').forEach((c,i)=>{{c.classList.toggle('active',i===v)}})}}}
function tog(e){{let c=e.nextElementSibling;c.style.display=c.style.display==='none'?'block':'none';e.innerHTML=c.style.display==='none'?'▶ '+e.innerHTML.slice(2):'▼ '+e.innerHTML.slice(2)}}}
function jump(i){{let s=document.getElementById('s'+i);s.scrollIntoView({{behavior:'smooth'}});let t=s.querySelector('.st'),c=s.querySelector('.sc');if(c.style.display==='none')tog(t)}}}
document.getElementById('sb').addEventListener('input',e=>{{let q=e.target.value.toLowerCase();document.querySelectorAll('.sec').forEach(s=>{{s.style.display=s.textContent.toLowerCase().includes(q)?'block':'none'}})}}});
</script></body></html>'''
    
    report_filename = f"report_{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    report_path = os.path.join('reports', report_filename)
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    return report_path


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        generate_html_report(sys.argv[1], 'test', 'linpeas')
        print(f"Report generated for {sys.argv[1]}")
