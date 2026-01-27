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
    
    # Patterns for important findings
    patterns = [
        (r'.*99%.*', 'critical'),  # Very high confidence findings
        (r'.*95%.*', 'high'),
        (r'.*password.*', 'high'),
        (r'.*root.*', 'medium'),
        (r'.*sudo.*', 'medium'),
        (r'.*writable.*', 'medium'),
    ]
    
    for line in content.split('\n'):
        for pattern, severity in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                highlights.append({
                    'severity': severity,
                    'content': line.strip()
                })
                break
    
    return highlights[:50]  # Limit to top 50


def generate_html_report(filepath, hostname, scan_type):
    """Generate interactive HTML report from scan output"""
    
    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()
    
    # Parse sections
    sections = parse_linpeas(content)
    highlights = extract_highlights(content)
    
    # Generate timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
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
        
        .section-content::-webkit-scrollbar {{
            width: 10px;
        }}
        
        .section-content::-webkit-scrollbar-track {{
            background: #0a0e27;
        }}
        
        .section-content::-webkit-scrollbar-thumb {{
            background: #00ff00;
            border-radius: 5px;
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
    
    <input type="text" class="search-box" id="searchBox" placeholder="🔍 Search output..." />
    
    <div class="highlights">
        <h2>⚠️ Critical Findings ({len(highlights)})</h2>
        {''.join([f'<div class="highlight-item {h["severity"]}">{escape(h["content"])}</div>' for h in highlights])}
    </div>
    
    <div id="sections">
        {''.join([f'''<div class="section" data-section="{escape(title)}">
            <div class="section-title" onclick="toggleSection(this)">▶ {escape(title)}</div>
            <div class="section-content" style="display: none;">{escape(content)}</div>
        </div>''' for title, content in sections.items()])}
    </div>
    
    <script>
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
        
        // Search functionality
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
    # Test with a sample file
    import sys
    if len(sys.argv) > 1:
        generate_html_report(sys.argv[1], 'test', 'linpeas')
