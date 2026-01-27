#!/usr/bin/env python3
"""
ParsingPeas Parser
Parses linpeas/winpeas output and generates interactive HTML reports
"""

import os
import re
import json
from datetime import datetime
from html import escape
from collections import OrderedDict


def strip_ansi_codes(text):
    """Remove ANSI color codes from text"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def extract_hostname(content):
    """Extract hostname from linpeas output"""
    clean = strip_ansi_codes(content)
    
    patterns = [
        r'Hostname:\s*([\w\-\.]+)',
        r'hostname=([\w\-\.]+)',
        r'\[\+\].*Hostname.*?:\s*([\w\-\.]+)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, clean, re.IGNORECASE)
        if match:
            hostname = match.group(1).strip()
            if hostname and hostname not in ['localhost', 'unknown']:
                return hostname
    
    return 'unknown'


def convert_ansi_to_html_colors(text, for_terminal=True):
    """
    Convert ANSI codes to colored HTML
    """
    lines = text.split('\n')
    result_lines = []
    
    for line in lines:
        is_header = '\x1B[1;32m' in line
        has_box = bool(re.search(r'[\u2554\u2557\u2551\u255a\u255d\u2550]', line))
        
        processed = line
        
        color_map = [
            (r'\x1B\[1;31m', '<span style="color:#ff6b6b;font-weight:bold">'),
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
        
        for pattern, replacement in color_map:
            processed = re.sub(pattern, replacement, processed)
        
        processed = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', processed)
        
        processed = processed.replace('&', '&amp;')
        processed = processed.replace('<', '&lt;').replace('>', '&gt;')
        processed = processed.replace('&lt;span', '<span').replace('&lt;/span&gt;', '</span>')
        processed = re.sub(r'style=&quot;([^&]+?)&quot;&gt;', r'style="\1">', processed)
        
        if for_terminal:
            if is_header and has_box:
                processed = f'<div class="term-header">{processed}</div>'
            else:
                processed = f'{processed}<br>'
        
        result_lines.append(processed)
    
    return '\n'.join(result_lines)


def categorize_sections(sections):
    """Organize sections into categories"""
    categories = OrderedDict()
    
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
    """Parse linpeas output"""
    lines = content.split('\n')
    sections = OrderedDict()
    current_section = None
    current_content = []
    header_count = 0
    
    for line in lines:
        has_bold_green = '\x1B[1;32m' in line
        has_box = bool(re.search(r'[\u2554\u2557\u2551\u255a\u255d\u2550]', line))
        clean_line = strip_ansi_codes(line).strip()
        
        if has_bold_green and has_box:
            if current_section and current_content:
                sections[current_section] = '\n'.join(current_content)
            
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


def generate_html_report(filepath, hostname=None, scan_type='linpeas'):
    """Generate interactive HTML report"""
    
    print(f"\n\U0001f539 Parsing {filepath}...\n")
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            raw_content = f.read()
    except:
        with open(filepath, 'rb') as f:
            raw_content = f.read().decode('utf-8', errors='ignore')
    
    if not hostname:
        print("\U0001f310 Extracting hostname...")
        hostname = extract_hostname(raw_content)
        print(f"  Hostname: {hostname}")
    
    print("\n\U0001f50d Detecting sections...")
    sections = parse_linpeas_by_ansi_colors(raw_content)
    
    if not sections:
        print("\u26a0\ufe0f  WARNING: No sections found!")
        return None
    
    print("\n\U0001f4c1 Organizing into categories...")
    categories = categorize_sections(sections)
    for cat_name, cat_sections in categories.items():
        print(f"  {cat_name}: {len(cat_sections)} sections")
    
    print("\n\u26a0\ufe0f  Extracting critical findings...")
    findings = extract_critical_findings(raw_content)
    print(f"  Found {len(findings)} critical findings")
    
    # Process terminal data: strip ANSI and chunk it
    timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    os.makedirs('reports', exist_ok=True)
    
    print("\n\U0001f4be Processing terminal data (chunked lazy loading)...")
    clean_terminal = strip_ansi_codes(raw_content)
    lines = clean_terminal.split('\n')
    total_lines = len(lines)
    
    # Create chunks of 500 lines each
    chunk_size = 500
    chunks = []
    for i in range(0, total_lines, chunk_size):
        chunk_lines = lines[i:i+chunk_size]
        chunks.append('\n'.join(chunk_lines))
    
    # Save chunks as JSON
    chunks_filename = f"terminal_{hostname}_{timestamp_str}.json"
    chunks_path = os.path.join('reports', chunks_filename)
    with open(chunks_path, 'w', encoding='utf-8') as f:
        json.dump({
            'total_lines': total_lines,
            'chunk_size': chunk_size,
            'chunks': chunks
        }, f)
    
    print(f"  Terminal data: {chunks_filename}")
    print(f"  Total lines: {total_lines:,} | Chunks: {len(chunks)} | Size: {len(clean_terminal):,} bytes")
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Generate hierarchical TOC
    toc_html = ''
    section_idx = 0
    for cat_name, cat_sections in categories.items():
        cat_id = cat_name.replace(' ', '_').replace('/', '_')
        toc_html += f'<li class="cat"><div class="cat-title" onclick="toggleCat(\'{cat_id}\')">& gt; {escape(cat_name)} ({len(cat_sections)})</div>'
        toc_html += f'<ul class="cat-sections" id="cat-{cat_id}" style="display:none">'
        for section_title in cat_sections:
            toc_html += f'<li><a href="#s{section_idx}" onclick="jump({section_idx}); return false;">{escape(section_title[:70])}</a></li>'
            section_idx += 1
        toc_html += '</ul></li>'
    
    # Generate sections - FIXED BRACES
    secs = ''.join([
        f'<div class="sec" id="s{i}">'
        f'<div class="st" onclick="tog(this)">v {escape(t)}</div>'
        f'<div class="sc">{convert_ansi_to_html_colors(c, for_terminal=False)}</div>'
        f'</div>'
        for i, (t, c) in enumerate(sections.items())
    ])
    
    # Generate findings
    finds = ''.join([f'<div class="f {f["severity"]}">{escape(f["content"])}</div>' for f in findings]) if findings else '<div class="nf">No critical findings detected</div>'
    
    # JavaScript with COMPREHENSIVE DEBUGGING
    javascript = f'''<script>
// ============ DEBUG SYSTEM ============
const DEBUG_MODE = true;
const debugLog = (msg, data) => {{
    const log = `[DEBUG] ${{msg}}`;
    console.log(log, data || '');
    if (DEBUG_MODE && document.getElementById('debug-console')) {{
        const div = document.createElement('div');
        div.textContent = log + (data ? ': ' + JSON.stringify(data).substring(0, 100) : '');
        document.getElementById('debug-console').appendChild(div);
    }}
}};

window.onerror = (msg, url, line, col, error) => {{
    debugLog('ERROR', {{msg, line, col, error: error?.toString()}});
    return false;
}};

debugLog('Script loaded');

// ============ CONSTANTS ============
const TERMINAL_DATA_FILE = '{chunks_filename}';
let terminalData = null;
let currentChunk = 0;
let isLoading = false;
let allLoaded = false;

debugLog('Terminal file', TERMINAL_DATA_FILE);

// ============ BASIC FUNCTIONS ============
function sw(v) {{
    try {{
        debugLog('Switching view to', v);
        
        const buttons = document.querySelectorAll('.vb');
        const views = document.querySelectorAll('.vc');
        
        debugLog('Found buttons', buttons.length);
        debugLog('Found views', views.length);
        
        buttons.forEach((b, i) => {{
            b.classList.toggle('active', i === v);
        }});
        
        views.forEach((c, i) => {{
            c.classList.toggle('active', i === v);
        }});
        
        debugLog('View switched');
        
        if (v === 1 && !terminalData) {{
            debugLog('Loading terminal data');
            loadTerminalData();
        }}
    }} catch(e) {{
        debugLog('ERROR in sw()', e.toString());
    }}
}}

function tog(e) {{
    try {{
        let c = e.nextElementSibling;
        c.style.display = c.style.display === 'none' ? 'block' : 'none';
        e.innerHTML = (c.style.display === 'none' ? '&gt; ' : 'v ') + e.innerHTML.slice(2);
    }} catch(e) {{
        debugLog('ERROR in tog()', e.toString());
    }}
}}

function toggleCat(id) {{
    try {{
        let cat = document.getElementById('cat-' + id);
        let title = event.target;
        cat.style.display = cat.style.display === 'none' ? 'block' : 'none';
        title.textContent = (cat.style.display === 'none' ? '> ' : 'v ') + title.textContent.substring(2);
    }} catch(e) {{
        debugLog('ERROR in toggleCat()', e.toString());
    }}
}}

function jump(i) {{
    try {{
        document.getElementById('s' + i).scrollIntoView({{behavior: 'smooth'}});
    }} catch(e) {{
        debugLog('ERROR in jump()', e.toString());
    }}
}}

// ============ TERMINAL LOADER ============
async function loadTerminalData() {{
    const pre = document.getElementById('terminal-pre');
    const status = document.getElementById('term-status');
    const loadBtn = document.getElementById('load-all-btn');
    
    try {{
        debugLog('Starting terminal load');
        status.textContent = 'Loading terminal data...';
        
        debugLog('Fetching', TERMINAL_DATA_FILE);
        const response = await fetch(TERMINAL_DATA_FILE);
        debugLog('Fetch response', {{ok: response.ok, status: response.status}});
        
        if (!response.ok) throw new Error('Failed to load: ' + response.status);
        
        debugLog('Parsing JSON');
        terminalData = await response.json();
        debugLog('Terminal data loaded', {{chunks: terminalData.chunks.length, lines: terminalData.total_lines}});
        
        // Render first chunk immediately
        debugLog('Rendering first chunk');
        debugLog('First chunk length', terminalData.chunks[0].length);
        debugLog('First 100 chars', terminalData.chunks[0].substring(0, 100));
        pre.innerText = terminalData.chunks[0];
        debugLog('Pre element textContent length after assignment', pre.textContent.length);
        currentChunk = 1;
        
        status.textContent = `Showing 1-${{Math.min(terminalData.chunk_size, terminalData.total_lines)}} of ${{terminalData.total_lines.toLocaleString()}} lines`;
        loadBtn.style.display = terminalData.chunks.length > 1 ? 'inline-block' : 'none';
        
        debugLog('Terminal ready');
        setupScrollObserver();
    }} catch(e) {{
        debugLog('ERROR loading terminal', e.toString());
        status.textContent = 'Error: ' + e.message;
        pre.textContent = `Failed to load terminal data.\\n\\nError: ${{e.message}}\\n\\nMake sure to open via http:// (not file:///)\\nRun: python3 -m http.server 8000`;
    }}
}}

function setupScrollObserver() {{
    debugLog('Setting up scroll observer');
    const container = document.getElementById('terminal-content');
    
    container.addEventListener('scroll', () => {{
        if (allLoaded || isLoading) return;
        
        const scrollPercent = (container.scrollTop + container.clientHeight) / container.scrollHeight;
        if (scrollPercent > 0.8) {{
            loadNextChunk();
        }}
    }});
}}

function loadNextChunk() {{
    if (!terminalData || currentChunk >= terminalData.chunks.length || isLoading) return;
    
    debugLog('Loading chunk', currentChunk);
    isLoading = true;
    const pre = document.getElementById('terminal-pre');
    const status = document.getElementById('term-status');
    
    pre.innerText += '\\n' + terminalData.chunks[currentChunk];
    currentChunk++;
    
    const linesShown = Math.min(currentChunk * terminalData.chunk_size, terminalData.total_lines);
    status.textContent = `Showing 1-${{linesShown.toLocaleString()}} of ${{terminalData.total_lines.toLocaleString()}} lines`;
    
    if (currentChunk >= terminalData.chunks.length) {{
        allLoaded = true;
        document.getElementById('load-all-btn').style.display = 'none';
        status.textContent = `All ${{terminalData.total_lines.toLocaleString()}} lines loaded`;
    }}
    
    isLoading = false;
}}

function loadAllChunks() {{
    if (!terminalData || allLoaded) return;
    
    debugLog('Loading all chunks');
    const pre = document.getElementById('terminal-pre');
    const status = document.getElementById('term-status');
    const btn = document.getElementById('load-all-btn');
    
    btn.textContent = 'Loading...';
    btn.disabled = true;
    
    setTimeout(() => {{
        const remaining = terminalData.chunks.slice(currentChunk);
        pre.innerText += '\\n' + remaining.join('\\n');
        
        currentChunk = terminalData.chunks.length;
        allLoaded = true;
        
        status.textContent = `All ${{terminalData.total_lines.toLocaleString()}} lines loaded`;
        btn.style.display = 'none';
        debugLog('All chunks loaded');
    }}, 10);
}}

// ============ SEARCH ============
const searchBox = document.getElementById('sb');
if (searchBox) {{
    searchBox.addEventListener('input', e => {{
        let q = e.target.value.toLowerCase();
        document.querySelectorAll('.sec').forEach(s => {{
            s.style.display = s.textContent.toLowerCase().includes(q) ? 'block' : 'none';
        }});
    }});
    debugLog('Search box initialized');
}}

// ============ INITIALIZATION ============
document.addEventListener('DOMContentLoaded', () => {{
    debugLog('DOM loaded');
    debugLog('All systems initialized');
}});

debugLog('ParsingPeas Debug Edition v2.2 loaded');
</script>'''
    
    # HTML template with DEBUG CONSOLE
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
.cat-sections{{margin-left:20px;margin-top:5px}}
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
.sc{{white-space:pre-wrap;font:13px 'Courier New',monospace;line-height:1.6;padding:15px;background:rgba(0,0,0,0.3);border-radius:5px;max-height:600px;overflow-y:auto}}
.raw{{background:#0d1117;padding:20px;border-radius:10px;border:2px solid #30363d;max-height:80vh;overflow-y:auto;position:relative}}
#terminal-pre{{color:#50fa7b;margin:0;white-space:pre-wrap;word-wrap:break-word;font:12px 'Courier New',monospace;line-height:1.6}}
.term-controls{{background:rgba(0,255,0,0.05);padding:12px;margin-bottom:15px;border-radius:5px;display:flex;align-items:center;justify-content:space-between;border:1px solid rgba(0,255,0,0.2)}}
#term-status{{color:#50fa7b;font-size:13px}}
#load-all-btn{{background:#00ff00;color:#0a0e27;border:none;padding:8px 16px;border-radius:4px;font:12px 'Courier New',monospace;font-weight:bold;cursor:pointer;transition:all .2s}}
#load-all-btn:hover{{background:#00cc00;transform:scale(1.05)}}
#load-all-btn:disabled{{opacity:0.5;cursor:not-allowed}}
#debug-console{{position:fixed;bottom:0;left:0;right:0;background:rgba(0,0,0,0.95);color:#0f0;padding:10px;font-size:11px;max-height:150px;overflow-y:auto;border-top:2px solid #0f0;font-family:monospace;z-index:9999}}
#debug-console div{{margin:2px 0;padding:2px;border-left:3px solid #0f0;padding-left:8px}}
.sc::-webkit-scrollbar,.toc::-webkit-scrollbar,.raw::-webkit-scrollbar{{width:10px}}
.sc::-webkit-scrollbar-track,.toc::-webkit-scrollbar-track,.raw::-webkit-scrollbar-track{{background:#0a0e27}}
.sc::-webkit-scrollbar-thumb,.toc::-webkit-scrollbar-thumb,.raw::-webkit-scrollbar-thumb{{background:#00ff00;border-radius:5px}}
</style></head><body>
<div class="hdr"><h1>ParsingPeas Report <small style="font-size:0.4em;color:#888">[DEBUG MODE]</small></h1>
<div class="info"><div><strong>Hostname:</strong> {escape(hostname)}</div><div><strong>Type:</strong> {escape(scan_type)}</div><div><strong>Generated:</strong> {timestamp}</div><div><strong>Sections:</strong> {len(sections)}</div></div></div>
<div><button class="vb active" onclick="sw(0)">Parsed</button><button class="vb" onclick="sw(1)">Terminal</button></div>
<div id="p" class="vc active">
<div class="toc"><h2>Contents ({len(categories)} categories)</h2><ul>{toc_html}</ul></div>
<input type="text" class="sb" id="sb" placeholder="Search..."/>
<div class="hl"><h2>Critical Findings ({len(findings)})</h2>{finds}</div>
<div>{secs}</div>
</div>
<div id="r" class="vc">
<div class="term-controls">
<span id="term-status">Click Terminal button to load...</span>
<button id="load-all-btn" onclick="loadAllChunks()" style="display:none">Load All</button>
</div>
<div class="raw" id="terminal-content"><pre id="terminal-pre"></pre></div>
</div>
<div id="debug-console"></div>
{javascript}
</body></html>'''
    
    report_filename = f"report_{hostname}_{timestamp_str}.html"
    report_path = os.path.join('reports', report_filename)
    
    with open(report_path, 'w', encoding='utf-8', errors='xmlcharrefreplace') as f:
        f.write(html)
    
    print(f"\n\u2705 Report generated: {report_path}")
    print(f"\u2705 Terminal data: {chunks_path}")
    print(f"\n\U0001f50d DEBUG MODE ENABLED - Check bottom of page for console logs\n")
    return report_path


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        result = generate_html_report(sys.argv[1])
    else:
        print("Usage: python3 parser.py <linpeas_output_file>")
