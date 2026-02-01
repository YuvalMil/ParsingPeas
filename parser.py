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


class AnsiConverter:
    """
    Handles conversion of ANSI codes to HTML for report viewing.
    Uses a state-machine approach to ensure flat, valid HTML spans.

    IMPORTANT:
    We must keep the original LinPEAS/WinPEAS coloring semantics.
    In particular, we should distinguish plain red text ("RED") from red/yellow
    combinations ("RED/YELLOW") by inspecting the actual ANSI SGR codes.
    """

    # Updated to standard terminal colors for better readability
    # (Foreground only; background handled separately.)
    COLORS = {
        '30': '#000000', '31': '#cc0000', '32': '#4e9a06', '33': '#c4a000',
        '34': '#3465a4', '35': '#75507b', '36': '#06989a', '37': '#d3d7cf',
        '90': '#555753', '91': '#ef2929', '92': '#8ae234', '93': '#fce94f',
        '94': '#729fcf', '95': '#ad7fa8', '96': '#34e2e2', '97': '#eeeeec',
    }

    # Background color mapping for the combinations LinPEAS commonly uses.
    # 41/101 => red bg, 43/103 => yellow bg.
    BG_COLORS = {
        '41': '#ff0000',
        '101': '#ff0000',
        '43': '#ffff00',
        '103': '#ffff00',
    }

    FG_RED = {'31', '91'}
    FG_YELLOW = {'33', '93'}
    FG_WHITE = {'37', '97'}
    BG_RED = {'41', '101'}
    BG_YELLOW = {'43', '103'}

    def to_html(self, text):
        parts = re.split(r'\x1b\[([\d;]*)m', text)
        result = []
        current_style = {'fg_code': None, 'bg_code': None, 'bold': False}

        def is_critical_combo(style):
            """Detect LinPEAS "RED/YELLOW" style combos."""
            fg = style.get('fg_code')
            bg = style.get('bg_code')

            # Red text on Yellow background (common LinPEAS RED/YELLOW)
            if bg in self.BG_YELLOW and fg in self.FG_RED:
                return True

            # Yellow/White text on Red background (also used by LinPEAS for criticals)
            if bg in self.BG_RED and (fg in self.FG_YELLOW or fg in self.FG_WHITE):
                return True

            return False

        def get_span_tag(style):
            css = []
            classes = []

            fg_hex = self.COLORS.get(style['fg_code']) if style.get('fg_code') else None
            bg_hex = self.BG_COLORS.get(style['bg_code']) if style.get('bg_code') else None

            if fg_hex:
                css.append(f"color:{fg_hex}")
            if style.get('bold'):
                css.append("font-weight:bold")
            if bg_hex:
                css.append(f"background-color:{bg_hex}")

            # Add a class for combo-critical so it can be visually distinct while still
            # keeping the original fg/bg colors.
            if is_critical_combo(style):
                classes.append('crit-combo')
                # Ensure it pops like the terminal does.
                if "font-weight:bold" not in css:
                    css.append("font-weight:bold")

            if not css and not classes:
                return ""

            class_attr = f' class="{" ".join(classes)}"' if classes else ''
            style_attr = f' style="{";".join(css)}"' if css else ''
            return f'<span{class_attr}{style_attr}>'

        if parts[0]:
            result.append(html.escape(parts[0]))

        for i in range(1, len(parts), 2):
            code_seq = parts[i]
            text_segment = parts[i + 1]
            codes = code_seq.split(';')

            for code in codes:
                if not code:
                    code = '0'

                if code == '0':
                    current_style = {'fg_code': None, 'bg_code': None, 'bold': False}
                elif code == '1':
                    current_style['bold'] = True
                elif code == '22':
                    current_style['bold'] = False
                elif code in self.COLORS:
                    current_style['fg_code'] = code
                elif code == '39':
                    current_style['fg_code'] = None
                elif code == '49':
                    current_style['bg_code'] = None
                elif code in self.BG_COLORS:
                    current_style['bg_code'] = code

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

    # 12 Granular Categories with Expanded Keywords
    CATEGORIES = {
        "System Information": [
            "Basic information", "System Information", "OS Information", "Environment",
            "Operative system", "Hostname", "Env", "Version", "Date & uptime", "PATH",
            "linuxONE", "Syslog configuration", "Basic System Information"
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

    ANSI_SGR_RE = re.compile(r'\x1b\[([\d;]*)m')
    
    # Section header color pattern: cyan (1;36m) followed by green (1;32m)
    HEADER_COLOR_PATTERN = re.compile(r'\x1b\[1;36m.*?\x1b\[1;32m')

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
        # Stats for reporting
        self.stats = {
            'sections_with_critical': 0,
            'sections_with_high': 0,
            'total_sections_with_findings': 0
        }

    def parse(self):
        self._strip_initial_banner()
        self._extract_hostname()
        self._extract_sections()
        self._organize_categories()
        self._extract_findings_contextual()
        self._calculate_stats()

    def _strip_initial_banner(self):
        """Remove the *ASCII art logo* but keep the PEASS credit box."""
        lines = self.raw_content.splitlines()

        # Prefer keeping the "Do you like PEASS?" box if present
        box_line_idx = None
        for i, line in enumerate(lines):
            clean = self.converter.strip(line).strip().lower()
            if 'do you like' in clean and 'peass' in clean:
                box_line_idx = i
                break

        if box_line_idx is not None:
            # Walk backwards to capture the full box border
            j = box_line_idx
            steps = 0
            while j > 0 and steps < 15:
                prev = lines[j - 1]
                # Look for box-drawing or color pattern
                if any(ch in prev for ch in '╔╗╚╝║═') or '\x1b[1;36m' in prev:
                    j -= 1
                    steps += 1
                    continue
                break

            if j > 0:
                self.raw_content = "\n".join(lines[j:])
                self.clean_content = self.converter.strip(self.raw_content)
            return

        # Fallback: strip everything before the first real section header
        for i, line in enumerate(lines):
            if self._is_section_header(line):
                if i > 0:
                    self.raw_content = "\n".join(lines[i:])
                    self.clean_content = self.converter.strip(self.raw_content)
                return

    def _is_section_header(self, line):
        """
        Detect if a line is a section header by ANSI color pattern.
        Headers use: cyan (1;36m) for decoration + green (1;32m) for title.
        This works regardless of character encoding corruption.
        """
        # Primary detection: cyan + green color pattern
        if self.HEADER_COLOR_PATTERN.search(line):
            return True
        
        # Fallback: standard Unicode box-drawing characters
        box_chars = '╔═╗╚╝║─│┌┐└┘├┤┬┴┼'
        if any(c in line for c in box_chars):
            clean = self.converter.strip(line).strip()
            # Headers usually have reasonable length
            if len(clean) < 100 and clean:
                return True
        
        # Fallback: [+] or [-] patterns that look like headers
        clean_line = self.converter.strip(line).strip()
        if clean_line.startswith('[+]') or clean_line.startswith('[-]'):
            # Headers are usually short and don't end with colons
            if len(clean_line) < 80 and not clean_line.endswith(':'):
                return True
        
        return False

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

        for line in lines:
            if self._is_section_header(line):
                # Save previous section
                if buffer:
                    if current_header in self.sections:
                        self.sections[current_header] += "\n" + "\n".join(buffer)
                    else:
                        self.sections[current_header] = "\n".join(buffer)
                    buffer = []

                # Extract title from the green text portion (after \x1b[1;32m)
                clean_line = self.converter.strip(line).strip()
                
                # Remove decorative characters (both standard and corrupted)
                # Standard: ╔═╗╚╝║ etc
                # Corrupted: อออน etc (Thai chars)
                # Also remove common symbols: []+-
                decorative_chars = '╔═╗╚╝║─│┌┐└┘├┤┬┴┼[]+-'
                title = clean_line.translate(str.maketrans('', '', decorative_chars)).strip()
                
                # Additional cleanup: remove any remaining Thai/corrupted chars
                # (they appear as non-ASCII in certain ranges)
                title = ''.join(c for c in title if ord(c) < 0x0E00 or ord(c) > 0x0E7F)
                title = title.strip()
                
                if title:
                    current_header = title
                buffer.append(line)
            else:
                buffer.append(line)

        # Save last section
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

    def _has_critical_combo(self, line):
        """True if the ANSI SGR sequences include a LinPEAS critical color combo."""
        for seq in self.ANSI_SGR_RE.findall(line):
            codes = set([c for c in seq.split(';') if c])

            # Red on Yellow background => critical (LinPEAS RED/YELLOW)
            if (('43' in codes or '103' in codes) and ('31' in codes or '91' in codes)):
                return True

            # Yellow/White on Red background => critical
            if (('41' in codes or '101' in codes) and (('33' in codes or '93' in codes) or ('37' in codes or '97' in codes))):
                return True

        return False

    def _has_red_text_no_critical_bg(self, line):
        """True if line contains red text, but not in a critical background combo."""
        for seq in self.ANSI_SGR_RE.findall(line):
            codes = set([c for c in seq.split(';') if c])

            has_red_fg = ('31' in codes or '91' in codes)
            has_bg = any(bg in codes for bg in ('41', '101', '43', '103'))

            if has_red_fg and not has_bg:
                return True

        return False

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

                # Critical: only when the actual ANSI uses a RED/YELLOW combo.
                if self._has_critical_combo(line):
                    level = 'critical'
                    found = True

                # High: red foreground only (no bg combination)
                elif self._has_red_text_no_critical_bg(line):
                    clean = self.converter.strip(line).strip()
                    # Enhanced False Positive filtering
                    if len(clean) > 200:
                        continue
                    if "Scan" in clean or "started" in clean:
                        continue
                    if "Use the" in clean:
                        continue
                    if "https://" in clean:
                        continue
                    if "Active Internet connections" in clean:
                        continue
                    if "Proto Recv-Q" in clean:
                        continue
                    if "Unknown SUID binary" in clean:
                        continue

                    level = 'high'
                    found = True

                if found:
                    clean_text = self.converter.strip(line).strip()
                    if clean_text:
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

    def _calculate_stats(self):
        """Calculate statistics based on sections with findings, not individual lines."""
        sections_with_critical = set()
        sections_with_high = set()
        
        for title, findings in self.section_findings.items():
            has_critical = any(f['level'] == 'critical' for f in findings)
            has_high = any(f['level'] == 'high' for f in findings)
            
            if has_critical:
                sections_with_critical.add(title)
            elif has_high:
                sections_with_high.add(title)
        
        self.stats['sections_with_critical'] = len(sections_with_critical)
        self.stats['sections_with_high'] = len(sections_with_high)
        self.stats['total_sections_with_findings'] = len(sections_with_critical) + len(sections_with_high)


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
        chunks = ['\n'.join(converted_lines[i:i + CHUNK_SIZE]) for i in range(0, len(converted_lines), CHUNK_SIZE)]

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

            # Calculate stats for this category - count SECTIONS not individual findings
            sections_with_crit = 0
            sections_with_high = 0
            for title in sections.keys():
                # Skip "General Information" from report summary
                if title == "General Information":
                    continue
                    
                if title in self.parser.section_findings:
                    findings = self.parser.section_findings[title]
                    has_critical = any(f['level'] == 'critical' for f in findings)
                    has_high = any(f['level'] == 'high' for f in findings)

                    if has_critical:
                        sections_with_crit += 1
                    elif has_high:
                        sections_with_high += 1

            stats_badge = ""
            if sections_with_crit > 0 or sections_with_high > 0:
                parts = []
                if sections_with_crit > 0:
                    parts.append(f"<span class='stat-crit'>{sections_with_crit}C</span>")
                if sections_with_high > 0:
                    parts.append(f"<span class='stat-high'>{sections_with_high}H</span>")
                stats_badge = f"<span class='cat-stats'>{' '.join(parts)}</span>"

            # Count sections for display (excluding General Information)
            visible_sections = [t for t in sections.keys() if t != "General Information"]
            if not visible_sections:
                continue

            toc_html.append(f'''
            <li class="category-group">
                <details open>
                    <summary>
                        <span>{html.escape(category_name)} <span class="count">{len(visible_sections)}</span></span>
                        {stats_badge}
                    </summary>
                    <ul>
            ''')

            for title, content in sections.items():
                # Skip "General Information" from report summary (still in terminal view)
                if title == "General Information":
                    continue
                    
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

        return HTML_TEMPLATE.format(
            hostname=self.parser.hostname,
            timestamp=self.timestamp,
            toc='\n'.join(toc_html),
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
        pre.content {{ white-space: pre; overflow-x: auto; font-family: 'Consolas', monospace; font-size: 0.9em; background: #15151a; padding: 20px; border-radius: 6px; border: 1px solid #2a2a2a; color: #ccc; line-height: 1.15; }}

        /* Combo-critical (RED/YELLOW etc) – keep original colors but make it pop. */
        .crit-combo {{ font-weight: bold !important; }}

        #terminal-view {{ background: #000; padding: 20px; }}
        #term-content {{ font-family: 'Consolas', monospace; font-size: 13px; color: #ccc; line-height: 1.15; white-space: pre; overflow-x: auto; }}
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
        print(f"[*] Detected {len(parser.sections)} sections")
        
        # Display section-based statistics instead of line counts
        stats = parser.stats
        if stats['total_sections_with_findings'] > 0:
            details = []
            if stats['sections_with_critical'] > 0:
                details.append(f"{stats['sections_with_critical']} critical")
            if stats['sections_with_high'] > 0:
                details.append(f"{stats['sections_with_high']} high")
            
            print(f"[*] Found {stats['total_sections_with_findings']} sections with findings ({', '.join(details)})")
        else:
            print("[*] No security findings detected")

    except Exception:
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
