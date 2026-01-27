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
    # Pattern to match ANSI escape sequences
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def ansi_to_html(text):
    """Convert ANSI color codes to HTML spans for terminal-style view"""
    # Color mappings
    color_map = {
        '0': '</span>',  # Reset
        '1': '<span style="font-weight:bold">',  # Bold
        '31': '<span style="color:#ff5555">',  # Red
        '32': '<span style="color:#50fa7b">',  # Green
        '33': '<span style="color:#f1fa8c">',  # Yellow
        '34': '<span style="color:#bd93f9">',  # Blue
        '35': '<span style="color:#ff79c6">',  # Magenta
        '36': '<span style="color:#8be9fd">',  # Cyan
        '37': '<span style="color:#f8f8f2">',  # White
        '1;31': '<span style="color:#ff5555;font-weight:bold">',
        '1;32': '<span style="color:#50fa7b;font-weight:bold">',
        '1;33': '<span style="color:#f1fa8c;font-weight:bold">',
        '1;34': '<span style="color:#bd93f9;font-weight:bold">',
        '1;35': '<span style="color:#ff79c6;font-weight:bold">',
        '1;36': '<span style="color:#8be9fd;font-weight:bold">',
    }
    
    # Replace ANSI codes with HTML
    result = text
    for code, html in color_map.items():
        result = result.replace(f'\x1B[{code}m', html)
    
    # Clean up any remaining ANSI codes
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    result = ansi_escape.sub('', result)
    
    return result


def parse_linpeas(content):
    """Parse linpeas output and extract key sections"""
    # Strip ANSI codes first
    content = strip_ansi_codes(content)
    
    sections = {}
    current_section = "General"
    current_content = []
    
    # Common section patterns in linpeas
    section_patterns = [
        r'═.*═',  # Section dividers
        r'╔.*╗',
        r'\[\+\].*',  # Important findings
    ]
    
    lines = content.split('\n')
    
    for line in lines:
        # Detect new section
        if any(re.search(pattern, line) for pattern in section_patterns):
            # Save previous section
            if current_content:
                sections[current_section] = '\n'.join(current_content)
            
            # Start new section
            current_section = line.strip()
            current_content = []
        else:
            current_content.append(line)
    
    # Save last section
    if current_content:
        sections[current_section] = '\n'.join(current_content)
    
    return sections


def extract_highlights(content):
    """Extract critical findings from output"""
    # Strip ANSI codes first
    content = strip_ansi_codes(content)
    
    highlights = []
    
    # Patterns for ACTUAL privilege escalation findings
    patterns = [
        (r'RED/YELLOW.*99%', 'critical'),
        (r'RED/YELLOW.*95%', 'critical'),
        (r'.*99%.*PE vector', 'critical'),
        (r'.*95%.*PE vector', 'high'),
        (r'.*NOPASSWD.*', 'high'),
        (r'.*\(ALL : ALL\).*', 'high'),
        (r'.*SUID.*writable', 'high'),
        (r'.*password.*found', 'high'),
        (r'.*Vulnerable to CVE.*', 'high'),
        (r'.*writable.*\.service', 'medium'),
        (r'.*writable.*cron', 'medium'),
        (r'.*writable.*\.sh', 'medium'),
        (r'.*world-writable', 'medium'),
        (r'.*Dirty.*Cow', 'critical'),
        (r'.*kernel.*exploit', 'high'),
    ]
    
    seen_lines = set()
    
    for line in content.split('\n'):
        line_stripped = line.strip()
        
        if not line_stripped or len(line_stripped) < 10:
            continue
            
        if '═' in line_stripped or '╔' in line_stripped or '╗' in line_stripped:
            continue
        
        for pattern, severity in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                if line_stripped not in seen_lines:
                    highlights.append({
                        'severity': severity,
                        'content': line_stripped
                    })
                    seen_lines.add(line_stripped)
                break
    
    return highlights[:50]


def generate_html_report(filepath, hostname, scan_type):
    """Generate interactive HTML report from scan output"""
    
    with open(filepath, 'r', errors='ignore') as f:
        raw_content = f.read()
    
    # Parse sections (clean version)
    sections = parse_linpeas(raw_content)
    highlights = extract_highlights(raw_content)
    
    # Convert raw content for terminal view
    terminal_html = ansi_to_html(escape(raw_content))
    
    # Generate timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Generate table of contents
    toc_items = ''.join([f'<li><a href="#section-{i}" onclick="scrollToSection({i})">{escape(title[:80])}</a></li>' 
                          for i, title in enumerate(sections.keys())])
    
    # Create HTML
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ParsingPeas Report - {escape(hostname)}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Courier New', monospace;
            background: #0a0e27;
            color: #00ff00;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            border: 2px solid #00ff00;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 0 0 10px #00ff00;
        }}
        
        .header .info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        
        .info-item {{
            background: rgba(0, 255, 0, 0.1);
            padding: 10px;
            border-radius: 5px;
            border-left: 3px solid #00ff00;
        }}
        
        .view-toggle {{
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }}
        
        .view-btn {{
            padding: 12px 24px;
            background: #1a1a2e;
            border: 2px solid #00ff00;
            color: #00ff00;
            cursor: pointer;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            transition: all 0.3s;
        }}
        
        .view-btn:hover {{
            background: rgba(0, 255, 0, 0.1);
        }}
        
        .view-btn.active {{
            background: #00ff00;
            color: #0a0e27;
            font-weight: bold;
        }}
        
        .view-content {{
            display: none;
        }}
        
        .view-content.active {{
            display: block;
        }}
        
        .toc {{
            background: #1a1a2e;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            border: 2px solid #00ff00;
            max-height: 400px;
            overflow-y: auto;
        }}
        
        .toc h2 {{
            margin-bottom: 15px;
            color: #00ff00;
        }}
        
        .toc ul {{
            list-style: none;
            column-count: 2;
            column-gap: 20px;
        }}
        
        .toc li {{
            margin: 5px 0;
            break-inside: avoid;
        }}
        
        .toc a {{
            color: #50fa7b;
            text-decoration: none;
            display: block;
            padding: 5px;
            border-radius: 3px;
            transition: all 0.2s;
        }}
        
        .toc a:hover {{
            background: rgba(0, 255, 0, 0.1);
            padding-left: 10px;
        }}
        
        .highlights {{
            background: #1a1a2e;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            border: 2px solid #ff6b6b;
        }}
        
        .highlights h2 {{
            color: #ff6b6b;
            margin-bottom: 15px;
        }}
        
        .highlight-item {{
            padding: 10px;
            margin: 5px 0;
            border-radius: 5px;
            border-left: 4px solid;
            font-size: 13px;
        }}
        
        .critical {{
            background: rgba(255, 0, 0, 0.2);
            border-left-color: #ff0000;
        }}
        
        .high {{
            background: rgba(255, 107, 107, 0.2);
            border-left-color: #ff6b6b;
        }}
        
        .medium {{
            background: rgba(255, 165, 0, 0.2);
            border-left-color: #ffa500;
        }}
        
        .search-box {{
            width: 100%;
            padding: 15px;
            background: #1a1a2e;
            border: 2px solid #00ff00;
            color: #00ff00;
            font-size: 16px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        
        .section {{
            background: #1a1a2e;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 10px;
            border: 1px solid #333;
            scroll-margin-top: 20px;
        }}
        
        .section-title {{
            color: #00ff00;
            cursor: pointer;
            padding: 10px;
            background: rgba(0, 255, 0, 0.1);
            border-radius: 5px;
            margin-bottom: 10px;
            user-select: none;
        }}
        
        .section-title:hover {{
            background: rgba(0, 255, 0, 0.2);
        }}
        
        .section-content {{
            white-space: pre-wrap;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.6;
            padding: 15px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 5px;
            max-height: 600px;
            overflow-y: auto;
        }}
        
        .section-content::-webkit-scrollbar,
        .toc::-webkit-scrollbar,
        .raw-output::-webkit-scrollbar {{
            width: 10px;
        }}
        
        .section-content::-webkit-scrollbar-track,
        .toc::-webkit-scrollbar-track,
        .raw-output::-webkit-scrollbar-track {{
            background: #0a0e27;
        }}
        
        .section-content::-webkit-scrollbar-thumb,
        .toc::-webkit-scrollbar-thumb,
        .raw-output::-webkit-scrollbar-thumb {{
            background: #00ff00;
            border-radius: 5px;
        }}
        
        .raw-output {{
            background: #1a1a2e;
            padding: 20px;
            border-radius: 10px;
            border: 2px solid #00ff00;
            white-space: pre-wrap;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.4;
            max-height: 80vh;
            overflow-y: auto;
            color: #f8f8f2;
        }}
        
        .no-findings {{
            color: #888;
            font-style: italic;
            padding: 15px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🥒 ParsingPeas Report</h1>
        <div class="info">
            <div class="info-item">
                <strong>Hostname:</strong> {escape(hostname)}
            </div>
            <div class="info-item">
                <strong>Scan Type:</strong> {escape(scan_type)}
            </div>
            <div class="info-item">
                <strong>Generated:</strong> {timestamp}
            </div>
            <div class="info-item">
                <strong>Sections:</strong> {len(sections)}
            </div>
        </div>
    </div>
    
    <div class="view-toggle">
        <button class="view-btn active" onclick="switchView('parsed')">📊 Parsed View</button>
        <button class="view-btn" onclick="switchView('raw')">💻 Raw Terminal View</button>
    </div>
    
    <!-- Parsed View -->
    <div id="parsed-view" class="view-content active">
        <div class="toc">
            <h2>📋 Table of Contents</h2>
            <ul>
                {toc_items}
            </ul>
        </div>
        
        <input type="text" class="search-box" id="searchBox" placeholder="🔍 Search parsed output..." />
        
        <div class="highlights">
            <h2>⚠️ Critical Findings ({len(highlights)})</h2>
            {('<div class="no-findings">No high-priority findings detected. Review sections below.</div>' if len(highlights) == 0 else ''.join([f'<div class="highlight-item {h["severity"]}">{escape(h["content"])}</div>' for h in highlights]))}
        </div>
        
        <div id="sections">
            {''.join([f'''<div class="section" id="section-{i}" data-section="{escape(title)}">
                <div class="section-title" onclick="toggleSection(this)">▶ {escape(title)}</div>
                <div class="section-content" style="display: none;">{escape(content)}</div>
            </div>''' for i, (title, content) in enumerate(sections.items())])}
        </div>
    </div>
    
    <!-- Raw Terminal View -->
    <div id="raw-view" class="view-content">
        <input type="text" class="search-box" id="searchBoxRaw" placeholder="🔍 Search raw output..." />
        <div class="raw-output" id="rawOutput">{terminal_html}</div>
    </div>
    
    <script>
        function switchView(view) {{
            const buttons = document.querySelectorAll('.view-btn');
            const contents = document.querySelectorAll('.view-content');
            
            buttons.forEach(btn => btn.classList.remove('active'));
            contents.forEach(content => content.classList.remove('active'));
            
            if (view === 'parsed') {{
                buttons[0].classList.add('active');
                document.getElementById('parsed-view').classList.add('active');
            }} else {{
                buttons[1].classList.add('active');
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
            // Auto-expand the section
            const title = section.querySelector('.section-title');
            const content = section.querySelector('.section-content');
            if (content.style.display === 'none') {{
                toggleSection(title);
            }}
        }}
        
        // Search functionality for parsed view
        document.getElementById('searchBox').addEventListener('input', function(e) {{
            const searchTerm = e.target.value.toLowerCase();
            const sections = document.querySelectorAll('.section');
            
            sections.forEach(section => {{
                const content = section.textContent.toLowerCase();
                if (content.includes(searchTerm)) {{
                    section.style.display = 'block';
                }} else {{
                    section.style.display = 'none';
                }}
            }});
        }});
        
        // Search functionality for raw view
        document.getElementById('searchBoxRaw').addEventListener('input', function(e) {{
            const searchTerm = e.target.value.toLowerCase();
            const rawOutput = document.getElementById('rawOutput');
            const originalText = rawOutput.textContent;
            
            if (searchTerm === '') {{
                // Reset highlighting
                location.reload();
                return;
            }}
            
            // Simple text highlight (basic implementation)
            const regex = new RegExp(searchTerm, 'gi');
            const highlighted = originalText.replace(regex, match => `<mark style="background: yellow; color: black;">${{match}}</mark>`);
            rawOutput.innerHTML = highlighted;
        }});
    </script>
</body>
</html>
    """
    
    # Save HTML report
    report_filename = f"report_{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    report_path = os.path.join('reports', report_filename)
    
    with open(report_path, 'w') as f:
        f.write(html)
    
    return report_path


if __name__ == '__main__':
    print("ParsingPeas Parser - Test mode")
    import sys
    if len(sys.argv) > 1:
        generate_html_report(sys.argv[1], 'test', 'linpeas')
