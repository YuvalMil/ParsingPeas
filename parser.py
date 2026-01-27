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
import hashlib
from datetime import datetime
from pathlib import Path
from collections import OrderedDict

# --- Configuration ---
CHUNK_SIZE = 2000  # Lines per chunk for terminal view loading

# Critical finding keywords for intelligent detection
# ONLY include high-confidence PE vectors here
CRITICAL_KEYWORDS = [
    # High confidence markers
    'PEASS', '95%', '99%', 'PE vector', 'RED/YELLOW', 'RED:',
    'possible CVE', 'Exploit',
    
    # Specific Dangerous Capabilities (Root equivalents)
    'cap_dac_override', 
    'cap_sys_admin', 
    'cap_sys_ptrace', 
    'cap_sys_module',
    'cap_chown',
    'cap_fowner',
    'cap_setuid',
    'cap_setgid',
    
    # Specific Critical Configurations
    'nopasswd', 'NOPASSWD',  # Sudo without password
    'git config', # Often contains creds
    'id_rsa', # Private keys
]

class AnsiConverter:
    """
    Handles conversion of ANSI codes to HTML for report viewing.
    Uses a state-machine approach to ensure flat, valid HTML spans.
    """

    # Updated to standard terminal colors for better readability
    COLORS = {
        '30': '#000000', '31': '#cc0000', '32': '#4e9a06', '33': '#c4a000',
        '34': '#3465a4', '35': '#75507b', '36': '#06989a', '37': '#d3d7cf',
        '90': '#555753', '91': '#ef2929', '92': '#8ae234', '93': '#fce94f',
        '94': '#729fcf', '95': '#ad7fa8', '96': '#34e2e2', '97': '#eeeeec',
    }

    def to_html(self, text):
        parts = re.split(r'\x1b\[([\d;]*)m', text)
        result = []
        current_style = {'color': None, 'bold': False, 'bg': None}

        def get_span_tag(text_content, style):
            css = []
            classes = []
            
            # CRITICAL FIX: Smart detection for critical patterns
            is_critical = False
            
            # Pattern 1: Red background = always critical
            if style['bg'] == '#ff0000':
                is_critical = True
            
            # Pattern 2: Specific critical keywords
            elif text_content:
                if any(kw in text_content for kw in ['RED/YELLOW', 'RED:']):
                    is_critical = True
                # Pattern 3: Bold red text ONLY if it contains LinPEAS critical indicators
                elif style['bold'] and style['color'] == '#cc0000':
                    if any(kw in text_content for kw in CRITICAL_KEYWORDS):
                        is_critical = True
            
            # Apply critical styling
            if is_critical:
                classes.append('crit-bg')
                css.append("color:#ffff00")
                css.append("background-color:#ff0000")
                css.append("font-weight:bold")
            else:
                # Normal processing for non-critical text
                if style['color']: 
                    css.append(f"color:{style['color']}")
                if style['bold']: 
                    css.append("font-weight:bold")
                if style['bg']: 
                    css.append(f"background-color:{style['bg']}")
            
            if not css and not classes: return ""
            
            class_attr = f' class="{" ".join(classes)}"' if classes else ''
            style_attr = f' style="{";".join(css)}"' if css else ''
            return f'<span{class_attr}{style_attr}>'

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
                span = get_span_tag(text_segment, current_style)
                if span:
                    result.append(f"{span}{html.escape(text_segment)}</span>")
                else:
                    result.append(html.escape(text_segment))

        return "".join(result)

    def strip(self, text):
        return re.sub(r'\x1b\[[\d;]*[a-zA-Z]', '', text)


class CategoryManager:
    """Manages the categorization of checks."""

    # 12 Granular Categories with Expanded Keywords
    CATEGORIES = {
        "System Information": [
            "Basic information", "System Information", "OS Information", "Environment",
            "Operative system", "Hostname", "Env", "Version", "Date & uptime", "PATH",
            "linuxONE", "Syslog configuration"
        ],
        "Kernel & Hardware": [
            "Kernel", "Loaded modules", "PCI devices", "USB devices",
            "Dmesg output", "System stats", "CPU", "Drivers", "Processor",
            "Virtual machine", "Module", "Signature enforcement", "lockdown mode",
            "sd*/disk*", "Printer"
        ],
        "Security & Defenses": [
            "AppArmor", "SELinux", "ASLR", "Grub configuration", "Auditd",
            "Defender", "Firewall", "Protections", "Security", "PaX", "Execshield",
            "Seccomp", "User namespace", "Cgroup2", "kptr_restrict", "dmesg_restrict",
            "ptrace_scope", "protected_symlinks", "protected_hardlinks", "perf_event_paranoid",
            "mmap_min_addr", "ld.so", "unpriv_userns_clone", "unpriv_bpf_disabled"
        ],
        "Network Information": [
            "Network Information", "Interfaces", "Ports", "Listening", "Routes",
            "DNS", "Hosts", "ARP", "Netstat", "Shares", "Iptables", "Nftables", "UFW",
            "Internet Access", "Sniffing Tools", "networkscripts", "SSH HostbasedAuthentication"
        ],
        "User Information": [
            "User Information", "Users & Groups", "Password Policy", "Logon Sessions",
            "LSA Secrets", "SAM", "Home folders", "Superusers", "Privileges",
            "Console", "Last logon", "Last logins", "Last time logon", "Logged in",
            "Sessions", "My user", "Sudo version", "sudo l", "sudo tokens",
            "Pkexec", "Polkit", "UID 0", "Failed login attempts", "Recent logins",
            "auth.log", "su", "passwd file", "shadow file", "opasswd"
        ],
        "Processes, Cron & Services": [
            "Processes Information", "Processes & Cron", "Services Information",
            "Systemd", "Cron", "Scheduled Tasks", "Autoruns", "Running Processes",
            "Binary processes", "Timers", "timer", "Sockets", "socket", "Task_work",
            "Opened Files by processes", "Processes with", "Service Files", "Active services",
            "Disabled services", "Services running as root", "DBus", "Inetd", "Xinetd",
            "rcommands", "rservice"
        ],
        "Software & Containers": [
            "Software Information", "Installed Software", "Compiler", "Container",
            "Docker", "Kubernetes", "LXC", "Useful Software", "Apache", "Nginx",
            "MariaDB", "Rsync", "PHP", "FastCGI", "Postfix", "Github", "FTP",
            "FreeIPA", "MySQL", "Postgres", "Mail"
        ],
        "Platform & Cloud": [
            "Cloud", "AWS", "GCP", "Azure", "EC2", "Metadata", "Droplet", "Aliyun", "Tencent"
        ],
        "Storage & Mounts": [
            "Mount points", "Disk space", "LVM information", "Partitions",
            "Drives", "NFS exports", "Unmounted filesystem", "disk in /dev", "disk in /dev"
        ],
        "Files & Permissions": [
            "File Information", "Interesting Files", "Registry Information",
            "Writable Files", "Capabilities", "SUID", "SGID", "Permission",
            "Deleted files", "ACLs", "Executable files", "Unexpected in",
            "Readable files", "Writable", "Files inside", "Hidden files",
            "Web files", "Backup", "profile.d", ".sh files",
            "Analyzing Interesting logs", "Interesting logs", "Analyzing Windows Files",
            "Windows Files", "Can I read", "Can I write", "Searching root files", "Searching folders owned"
        ],
        "Credentials & Secrets": [
            "Searching passwords", "Credentials", "API Keys", "Passwords", "Identities",
            "SSH Keys", "History Files", "Browser", "Mails", "GPG keys", "Keyring", "Clipboard",
            "PGP", "PAM Auth", "Ldap Files", "SSH Files", "Certificates", "ssh and gpg agents",
            "ssh config", "hashes", "shadow plists", "tables inside", ".db", ".sql", ".sqlite"
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
        self.findings = []
        self.section_findings = {}
        self.hostname = "unknown"
        self.section_ids = {}
        self.seen_findings = set()

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
                if any(c in line for c in '╔═══'):
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
        self.findings = []
        self.section_findings = {}
        self.seen_findings = set()

        for title, content in self.sections.items():
            lines = content.splitlines()
            sec_id = self.section_ids.get(title, "")
            current_section_findings = []

            for line in lines:
                found = False
                level = ""

                # Robust Critical/High detection
                # LinPEAS critical = White(37) on Red(41) => \x1b[1;37;41m
                # Also common: \x1b[1;31;103m (Red on Yellow)
                if ';41m' in line or ';103m' in line:
                    level = 'critical'
                    found = True
                elif '1;31m' in line: # Bold Red
                    clean = self.converter.strip(line).strip()
                    # Enhanced False Positive filtering
                    if len(clean) > 200: continue # Skip ultra-long lines
                    if "Scan" in clean or "started" in clean: continue
                    if "Use the" in clean: continue
                    if "https://" in clean: continue # URLs often red but not findings
                    if "Active Internet connections" in clean: continue
                    if "Proto Recv-Q" in clean: continue
                    if "Unknown SUID binary" in clean: continue # Often misclassified
                    
                    level = 'high'
                    found = True

                if found:
                    clean_text = self.converter.strip(line).strip()
                    if clean_text:
                        # De-duplication using hash of text
                        text_hash = hashlib.md5(clean_text.encode()).hexdigest()
                        if text_hash not in self.seen_findings:
                            finding_obj = {
                                'level': level,
                                'text': clean_text,
                                'section': title,
                                'section_id': sec_id
                            }
                            self.findings.append(finding_obj)
                            current_section_findings.append(finding_obj)
                            self.seen_findings.add(text_hash)

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

        for category_name, sections in self.parser.categorized_sections.items():
            if not sections:
                continue
            
            # FIX: Calculate stats for this category - count SECTIONS not individual findings
            sections_with_crit = 0
            sections_with_high = 0
            for title in sections.keys():
                if title in self.parser.section_findings:
                    findings = self.parser.section_findings[title]
                    has_critical = any(f['level'] == 'critical' for f in findings)
                    has_high = any(f['level'] == 'high' for f in findings)
                    
                    if has_critical:
                        sections_with_crit += 1
                    elif has_high:  # Only count as 'high' if no critical
                        sections_with_high += 1
            
            stats_badge = ""
            if sections_with_crit > 0 or sections_with_high > 0:
                parts = []
                if sections_with_crit > 0: parts.append(f"<span class='stat-crit'>{sections_with_crit}C</span>")
                if sections_with_high > 0: parts.append(f"<span class='stat-high'>{sections_with_high}H</span>")
                stats_badge = f"<span class='cat-stats'>{' '.join(parts)}</span>"

            toc_html.append(f'''
            <li class="category-group">
                <details open>
                    <summary>
                        <span>{html.escape(category_name)} <span class="count">{len(sections)}</span></span>
                        {stats_badge}
                    </summary>
                    <ul>
            ''')

            for title, content in sections.items():
                if not content.strip():
                    continue
                safe_title = html.escape(title)
                sec_id = self.parser.section_ids[title]

                indicator = ''
                if title in self.parser.section_findings:
                    findings = self.parser.section_findings[title]
                    has_critical = any(f['level'] == 'critical' for f in findings)
                    if has_critical:
                        indicator = f'<span class="toc-finding-dot critical" onclick="toggleRead(this, event)" title="Click to mark read"></span>'
                    else:
                        indicator = f'<span class="toc-finding-dot high" onclick="toggleRead(this, event)" title="Click to mark read"></span>'

                toc_html.append(f'<li><a href="#{sec_id}"><span class="toc-title">{safe_title}</span>{indicator}</a></li>')

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


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <title>ParsingPeas: {hostname}</title>
    <style>
        :root {{
            --bg: #0f0f12;
            --text: #e0e0e0;
            --accent: #00ff00;
            --panel: #1a1a1f;
            --border: #333;
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
        .nav-controls {{ padding: 10px; display: flex; gap: 5px; border-bottom: 1px solid var(--border); }}
        .nav-btn {{ flex: 1; background: #25252b; color: #aaa; border: 1px solid #444; border-radius: 4px; padding: 4px; cursor: pointer; font-size: 0.8em; }}
        .nav-btn:hover {{ color: #fff; border-color: #666; }}
        details {{ margin-bottom: 5px; }}
        summary {{ cursor: pointer; padding: 10px; background: rgba(255,255,255,0.03); border-radius: 4px; font-weight: bold; font-size: 0.9em; list-style: none; display: flex; justify-content: space-between; align-items: center; transition: background 0.2s; }}
        summary:hover {{ background: rgba(255,255,255,0.08); color: #fff; }}
        summary::-webkit-details-marker {{ display: none; }}
        details[open] summary {{ color: var(--accent); }}
        details li a {{ display: flex; align-items: center; padding: 8px 15px 8px 25px; color: #888; text-decoration: none; font-size: 0.85em; transition: 0.2s; border-left: 2px solid transparent; }}
        details li a:hover {{ color: white; background: rgba(255,255,255,0.05); }}
        .toc-title {{ flex: 1 1 auto; min-width: 0; overflow-wrap: anywhere; }}
        .toc-finding-dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-left: auto; cursor: pointer; transition: opacity 0.2s; flex: 0 0 auto; }}
        .toc-finding-dot:hover {{ transform: scale(1.2); }}
        .toc-finding-dot.high {{ background: var(--high-fg); box-shadow: 0 0 5px var(--high-fg); }}
        .toc-finding-dot.critical {{ background: var(--critical-bg); border: 2px solid var(--critical-fg); box-shadow: 0 0 5px var(--critical-bg); width: 8px; height: 8px; }}
        .toc-finding-dot.read {{ background: #444 !important; border-color: #444 !important; box-shadow: none !important; opacity: 0.5; }}

        .cat-stats {{ font-size: 0.8em; display: flex; gap: 5px; }}
        .stat-crit {{ color: var(--critical-fg); background: var(--critical-bg); padding: 1px 4px; border-radius: 3px; font-weight: bold; }}
        .stat-high {{ color: #000; background: var(--high-fg); padding: 1px 4px; border-radius: 3px; font-weight: bold; }}

        .count {{ font-size: 0.8em; opacity: 0.5; font-weight: normal; background: #333; padding: 2px 6px; border-radius: 10px; margin-left: 5px; }}
        main {{ flex: 1; display: flex; flex-direction: column; overflow: hidden; }}
        header {{ padding: 15px 30px; background: var(--panel); border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }}
        .tabs button {{ background: transparent; border: none; color: #888; padding: 8px 16px; cursor: pointer; font-size: 1em; border-radius: 4px; transition: 0.2s; font-weight: bold; }}
        .tabs button.active {{ color: var(--bg); background: var(--accent); }}
        .meta-info {{ font-size: 0.85em; color: #666; }}
        .view {{ display: none; flex: 1; overflow-y: auto; padding: 30px; scroll-behavior: smooth; }}
        .view.active {{ display: block; }}
        #findings-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 15px; margin-bottom: 40px; }}
        .finding-card {{ background: #25252b; border: 1px solid #444; border-radius: 8px; padding: 20px; cursor: pointer; transition: all 0.2s; display: flex; flex-direction: column; gap: 10px; }}
        .finding-card:hover {{ transform: translateY(-3px); border-color: #777; box-shadow: 0 5px 15px rgba(0,0,0,0.3); }}
        .finding-card.critical {{ border-top: 4px solid var(--critical-bg); box-shadow: 0 0 10px var(--critical-glow) inset; }}
        .finding-card.high {{ border-top: 4px solid var(--high-fg); }}
        .finding-header {{ font-weight: bold; font-size: 1.1em; color: #fff; margin-bottom: 5px; }}
        .finding-stats {{ display: flex; gap: 10px; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8em; color: #000; }}
        .badge.critical {{ background: var(--critical-bg); color: var(--critical-fg); text-shadow: 1px 1px 0 #000; }}
        .badge.high {{ background: var(--high-fg); color: #000; }}
        .finding-footer {{ font-size: 0.8em; color: #666; margin-top: auto; text-align: right; }}
        .report-section {{ margin-bottom: 50px; scroll-margin-top: 20px; }}
        .section-header {{ display: flex; align-items: center; gap: 15px; margin-bottom: 15px; border-bottom: 1px solid #333; padding-bottom: 10px; }}
        .section-category {{ font-size: 0.7em; text-transform: uppercase; letter-spacing: 1px; color: #666; border: 1px solid #333; padding: 4px 8px; border-radius: 4px; }}
        .section-header h3 {{ color: var(--accent); margin: 0; font-size: 1.3em; }}
        .top-link {{ margin-left: auto; color: #666; text-decoration: none; font-size: 0.8em; }}
        pre.content {{ white-space: pre-wrap; font-family: 'Consolas', monospace; font-size: 0.9em; background: #15151a; padding: 20px; border-radius: 6px; border: 1px solid #2a2a2a; color: #ccc; line-height: 1.5; }}
        
        /* Critical background styling - use class-based targeting */
        .crit-bg {{ color: #ffff00 !important; background-color: #ff0000 !important; font-weight: bold !important; padding: 2px 4px; border-radius: 2px; }}

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
        <div class=\"brand\">ParsingPeas</div>
        <div class=\"nav-controls\">
            <button class=\"nav-btn\" onclick=\"expandAll(true)\">+ Open All</button>
            <button class=\"nav-btn\" onclick=\"expandAll(false)\">- Close All</button>
        </div>
        <nav>
            <ul>
                {toc}
            </ul>
        </nav>
    </aside>
    <main>
        <header>
            <div class=\"tabs\">
                <button class=\"active\" onclick=\"switchView('report')\">Report Summary</button>
                <button onclick=\"switchView('terminal')\">Full Terminal Output</button>
            </div>
            <div class=\"meta-info\">Host: <strong>{hostname}</strong> | {timestamp}</div>
        </header>
        <div id=\"report-view\" class=\"view active\">
            <h2 style=\"color:white; margin-top:0\">Critical Findings</h2>
            <div id=\"findings-grid\">{findings}</div>
            <hr style=\"border:0; border-top:1px solid #333; margin: 40px 0;\">
            {content}
        </div>
        <div id=\"terminal-view\" class=\"view\">
            <pre id=\"term-content\"></pre>
        </div>
        <div id=\"loading\">Loading...</div>
    </main>
    <script>
        const TERMINAL_FILE = '{json_file}';
        let terminalLoaded = false;
        let chunks = [];
        let nextChunkIdx = 0;
        function expandAll(open) {{ document.querySelectorAll('details').forEach(el => el.open = open); }}
        function switchView(viewName) {{
            document.querySelectorAll('.view').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tabs button').forEach(el => el.classList.remove('active'));
            document.getElementById(viewName + '-view').classList.add('active');
            const btns = document.querySelectorAll('.tabs button');
            if (viewName === 'report') btns[0].classList.add('active'); else btns[1].classList.add('active');
            if (viewName === 'terminal' && !terminalLoaded) {{ loadTerminal(); }}
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
            if (e.target.scrollHeight - e.target.scrollTop - e.target.clientHeight < 400) {{ renderNextChunk(); }}
        }});
        // --- Toggle Read Status ---
        function toggleRead(el, event) {{
            event.preventDefault();
            event.stopPropagation();
            el.classList.toggle('read');
        }}
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

    except Exception:
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
