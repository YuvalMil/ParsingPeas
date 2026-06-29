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

    # linpeas renders a two-level hierarchy with blue (1;34m) box art and green
    # (1;32m) titles. We must distinguish the genuine headers from the check
    # lines and hacktricks links that share the same colours, otherwise the
    # report fragments into hundreds of junk sections.
    #
    #   Major:  ...═══╣ <green>TITLE<blue> ╠═══...      (boxed, opens AND closes)
    #   Sub:    <blue>╔════╣ <green>TITLE                (opens with ╔, no close)
    #   Check:  <blue>═╣ <green>Question? ....           (NO leading ╔  -> content)
    #   Link:   <blue>╚ <italic>https://...              (leading ╚     -> content)
    MAJOR_HEADER_RE = re.compile(r'╣\s*\x1b\[1;32m\s*(.+?)\s*\x1b\[1;3[46]m\s*╠')
    SUB_HEADER_RE = re.compile(r'^(?:\x1b\[0m)?\x1b\[1;34m╔[═]+╣\s*\x1b\[1;32m\s*(.+?)\s*$')

    def __init__(self, content):
        self.raw_content = content
        self.converter = AnsiConverter()
        self.clean_content = self.converter.strip(content)
        self.sections = OrderedDict()
        self.section_major = {}   # section title -> owning linpeas major section
        self.major_order = []     # major section titles, in document order
        self.categorized_sections = OrderedDict()
        self.findings = []
        self.section_findings = {}
        self.hostname = "unknown"
        self.current_user = ""
        self.os_info = ""
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
        self._extract_meta()
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

    def _classify_header(self, line):
        """Classify a line as a linpeas section header.

        Returns ('major', title) or ('sub', title) for genuine headers, and
        (None, None) for everything else. Crucially, individual check lines
        (``═╣ Question? ....``), hacktricks links (``╚ https://...``) and bare
        box borders are *not* headers - they are content of their parent
        section.
        """
        m = self.MAJOR_HEADER_RE.search(line)
        if m:
            title = self.converter.strip(m.group(1)).strip()
            if title:
                return 'major', title

        s = self.SUB_HEADER_RE.match(line)
        if s:
            title = self.converter.strip(s.group(1)).strip()
            if title:
                return 'sub', title

        # Plaintext fallback (output captured with no ANSI colours): only a
        # box-art line that *opens* a section (╔ ... ╣) counts as a header.
        if '\x1b[' not in line:
            stripped = line.strip()
            if stripped.startswith('╔') and '╣' in stripped:
                title = stripped.lstrip('╔═╣ ').strip()
                if title and len(title) < 100:
                    return 'sub', title

        return None, None

    def _is_section_header(self, line):
        """True if the line opens a (major or sub) linpeas section."""
        tier, _ = self._classify_header(line)
        return tier is not None

    def _is_decoration(self, line):
        """True for pure box-border lines (e.g. the ╔═══╗ / ╚═══╝ that frame a
        major header) that carry no information and only add visual noise to a
        section body."""
        clean = self.converter.strip(line)
        clean = clean.translate(str.maketrans('', '', '╔═╗╚╝║╣╠┌┐└┘├┤┬┴┼─│ \t'))
        return clean == ''

    def _extract_hostname(self):
        match = re.search(r'Hostname:\s*([\w\-\.]+)', self.clean_content, re.IGNORECASE)
        if match:
            self.hostname = match.group(1).strip()
        elif "hostname" in self.clean_content.lower():
            for line in self.clean_content.splitlines():
                if line.lower().startswith("hostname:"):
                    self.hostname = line.split(":", 1)[1].strip()
                    break

    def _extract_meta(self):
        """Pull a couple of at-a-glance facts (current user, OS) for the report
        header badges. Best-effort; absent matches just leave the badge off."""
        m = re.search(r'uid=\d+\(([^)]+)\)', self.clean_content)
        if m:
            self.current_user = m.group(1).strip()

        m = re.search(r'^OS:\s*(.+)$', self.clean_content, re.MULTILINE)
        if not m:
            m = re.search(r'^\s*Description:\s*(.+)$', self.clean_content, re.MULTILINE)
        if m:
            self.os_info = m.group(1).strip()[:70]

    def _extract_sections(self):
        """Split the output into sections following linpeas' major/sub hierarchy.

        Header lines themselves are not copied into the section body (the
        section's ``<h3>`` already shows the title); only the lines *between*
        headers become content. A major header with no direct content yields an
        empty section, which the report builder simply skips.
        """
        lines = self.raw_content.splitlines()
        current_major = "General Information"
        current_title = "General Information"
        buffer = []

        def flush():
            if not buffer:
                return
            text = "\n".join(buffer)
            if current_title in self.sections:
                self.sections[current_title] += "\n" + text
            else:
                self.sections[current_title] = text
                self.section_major[current_title] = current_major

        for line in lines:
            tier, title = self._classify_header(line)
            if tier:
                flush()
                buffer = []
                if tier == 'major':
                    current_major = title
                    if title not in self.major_order:
                        self.major_order.append(title)
                    current_title = title
                else:  # sub
                    key = title
                    n = 2
                    while key in self.sections or key == current_title:
                        key = f"{title} ({n})"
                        n += 1
                    current_title = key
                # Reserve the section so duplicate-title detection works even
                # before any content is flushed.
                self.sections.setdefault(current_title, "")
                self.section_major[current_title] = current_major
            elif not self._is_decoration(line):
                buffer.append(line)

        flush()

    def _organize_categories(self):
        """Group sections for the TOC.

        Preferred grouping uses linpeas' own major sections (faithful and far
        more reliable than keyword guessing). When no major headers were found
        - e.g. WinPEAS or plaintext output - fall back to the keyword
        categoriser.
        """
        if self.major_order:
            groups = list(self.major_order)
            if any(self.section_major.get(t, "General Information") == "General Information"
                   for t in self.sections):
                groups.insert(0, "General Information")
            for grp in groups:
                self.categorized_sections.setdefault(grp, OrderedDict())

            idx = 0
            for title, content in self.sections.items():
                grp = self.section_major.get(title, "General Information")
                self.categorized_sections.setdefault(grp, OrderedDict())[title] = content
                self.section_ids[title] = f"s{idx}"
                idx += 1
        else:
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

    def _section_level(self, title):
        """'critical', 'high' or '' for a section, based on its findings."""
        findings = self.parser.section_findings.get(title)
        if not findings:
            return ''
        if any(f['level'] == 'critical' for f in findings):
            return 'critical'
        if any(f['level'] == 'high' for f in findings):
            return 'high'
        return ''

    def _build_html(self, json_file):
        toc_html = []
        content_html = []
        converter = AnsiConverter()

        for category_name, sections in self.parser.categorized_sections.items():
            if not sections:
                continue

            # Per-category finding counts (sections, not lines).
            sections_with_crit = 0
            sections_with_high = 0
            for title in sections.keys():
                if title == "General Information":
                    continue
                lvl = self._section_level(title)
                if lvl == 'critical':
                    sections_with_crit += 1
                elif lvl == 'high':
                    sections_with_high += 1

            stats_badge = ""
            if sections_with_crit > 0 or sections_with_high > 0:
                parts = []
                if sections_with_crit > 0:
                    parts.append(f"<span class='stat-crit'>{sections_with_crit}C</span>")
                if sections_with_high > 0:
                    parts.append(f"<span class='stat-high'>{sections_with_high}H</span>")
                stats_badge = f"<span class='cat-stats'>{' '.join(parts)}</span>"

            # Count sections for display (excluding General Information and
            # empty major-overview sections, which are skipped when rendered).
            visible_sections = [t for t, c in sections.items()
                                if t != "General Information" and c.strip()]
            if not visible_sections:
                continue

            cat_finding_cls = ' cat-has-finding' if (sections_with_crit or sections_with_high) else ''
            toc_html.append(f'''
            <li class="category-group{cat_finding_cls}">
                <details open>
                    <summary>
                        <span>{html.escape(category_name)} <span class="count">{len(visible_sections)}</span></span>
                        {stats_badge}
                    </summary>
                    <ul>
            ''')

            for title, content in sections.items():
                if title == "General Information":
                    continue
                if not content.strip():
                    continue
                safe_title = html.escape(title)
                sec_id = self.parser.section_ids[title]
                lvl = self._section_level(title)

                indicator = ''
                a_cls = 'toc-link'
                if lvl:
                    a_cls += ' has-finding'
                    indicator = (f'<span class="toc-finding-dot {lvl}" data-sid="{sec_id}" '
                                 f'onclick="toggleRead(this, event)" title="Click to mark read"></span>')

                toc_html.append(f'<li><a class="{a_cls}" href="#{sec_id}">'
                                f'<span class="toc-title">{safe_title}</span>{indicator}</a></li>')

                colored_content = converter.to_html(content)
                sec_cls = 'report-section'
                if lvl:
                    sec_cls += f' has-finding has-{lvl}'

                content_html.append(f'''
                    <section id="{sec_id}" class="{sec_cls}">
                        <div class="section-header">
                            <span class="section-category">{html.escape(category_name)}</span>
                            <h3>{safe_title}</h3>
                            <a href="#" class="top-link">↑ Top</a>
                        </div>
                        <pre class="content">{colored_content}</pre>
                    </section>
                ''')

            toc_html.append('</ul></details></li>')

        ncrit = self.parser.stats['sections_with_critical']
        nhigh = self.parser.stats['sections_with_high']
        if ncrit or nhigh:
            findings_summary = (
                f'<button class="fb-chip crit" onclick="jumpFinding(\'critical\')">'
                f'{ncrit} critical</button>'
                f'<button class="fb-chip high" onclick="jumpFinding(\'high\')">'
                f'{nhigh} high</button>')
        else:
            findings_summary = '<span class="fb-none">No red / critical findings flagged</span>'

        user = self.parser.current_user
        user_badge = ''
        if user:
            ucls = 'hdr-badge user' + (' root' if user == 'root' else '')
            user_badge = f'<span class="{ucls}" title="Current user">&#128100; {html.escape(user)}</span>'
        os_badge = ''
        if self.parser.os_info:
            os_badge = f'<span class="hdr-badge" title="OS">&#128187; {html.escape(self.parser.os_info)}</span>'

        report_id = f"{self.parser.hostname}_{self.timestamp}"

        return HTML_TEMPLATE.format(
            hostname=html.escape(self.parser.hostname),
            timestamp=self.timestamp,
            toc='\n'.join(toc_html),
            content='\n'.join(content_html),
            json_file=json_file,
            findings_summary=findings_summary,
            user_badge=user_badge,
            os_badge=os_badge,
            report_id=html.escape(report_id),
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
        .nav-controls {{ padding: 10px; display: flex; gap: 5px; border-bottom: 1px solid var(--border); flex-wrap: wrap; }}
        .nav-btn {{ flex: 1; background: #25252b; color: #aaa; border: 1px solid #444; border-radius: 4px; padding: 4px; cursor: pointer; font-size: 0.8em; }}
        .nav-btn:hover {{ color: #fff; border-color: #666; }}
        .nav-toggle {{ flex: 1 1 45%; display: flex; align-items: center; gap: 6px; color: #aaa; font-size: 0.78em; cursor: pointer; }}
        .nav-toggle input {{ accent-color: var(--accent); cursor: pointer; }}
        details {{ margin-bottom: 5px; }}
        summary {{ cursor: pointer; padding: 10px; background: rgba(255,255,255,0.03); border-radius: 4px; font-weight: bold; font-size: 0.9em; list-style: none; display: flex; justify-content: space-between; align-items: center; transition: background 0.2s; }}
        summary:hover {{ background: rgba(255,255,255,0.08); color: #fff; }}
        summary::-webkit-details-marker {{ display: none; }}
        details[open] summary {{ color: var(--accent); }}
        details li a {{ display: flex; align-items: center; padding: 8px 15px 8px 25px; color: #888; text-decoration: none; font-size: 0.85em; transition: 0.2s; border-left: 2px solid transparent; }}
        details li a:hover {{ color: white; background: rgba(255,255,255,0.05); }}
        details li a.active {{ color: #fff; background: rgba(0,255,0,0.08); border-left-color: var(--accent); }}
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
        header {{ padding: 15px 30px; background: var(--panel); border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; gap: 15px; }}
        .tabs button {{ background: transparent; border: none; color: #888; padding: 8px 16px; cursor: pointer; font-size: 1em; border-radius: 4px; transition: 0.2s; font-weight: bold; }}
        .tabs button.active {{ color: var(--bg); background: var(--accent); }}
        .meta-info {{ font-size: 0.85em; color: #666; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; justify-content: flex-end; }}
        .hdr-badge {{ background: #25252b; border: 1px solid #444; color: #bbb; padding: 3px 9px; border-radius: 12px; font-size: 0.95em; white-space: nowrap; }}
        .hdr-badge.user {{ color: var(--accent); border-color: #2c5; }}
        .hdr-badge.user.root {{ color: var(--critical-fg); background: var(--critical-bg); border-color: var(--critical-bg); font-weight: bold; }}
        .view {{ display: none; flex: 1; overflow-y: auto; padding: 0; scroll-behavior: smooth; }}
        .view.active {{ display: block; }}
        .report-body {{ padding: 20px 30px 40px; }}

        /* Findings bar */
        #findings-bar {{ display: flex; align-items: center; gap: 15px; flex-wrap: wrap; padding: 12px 30px; background: #15151a; border-bottom: 1px solid var(--border); }}
        #findings-bar .fb-label {{ color: #888; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; }}
        .fb-chip {{ border: none; border-radius: 14px; padding: 5px 12px; font-weight: bold; font-size: 0.85em; cursor: pointer; }}
        .fb-chip.crit {{ background: var(--critical-bg); color: var(--critical-fg); }}
        .fb-chip.high {{ background: var(--high-fg); color: #000; }}
        .fb-chip:hover {{ filter: brightness(1.15); }}
        .fb-none {{ color: #6a6; font-size: 0.9em; }}
        .legend {{ margin-left: auto; display: flex; gap: 14px; color: #888; font-size: 0.8em; align-items: center; }}
        .lg-dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 4px; vertical-align: middle; }}
        .lg-dot.crit {{ background: var(--critical-bg); border: 2px solid var(--critical-fg); }}
        .lg-dot.high {{ background: var(--high-fg); }}

        .report-section {{ margin-bottom: 50px; scroll-margin-top: 60px; }}
        .section-header {{ display: flex; align-items: center; gap: 15px; margin-bottom: 15px; border-bottom: 1px solid #333; padding: 10px 0; position: sticky; top: 0; background: var(--bg); z-index: 5; }}
        .section-category {{ font-size: 0.7em; text-transform: uppercase; letter-spacing: 1px; color: #666; border: 1px solid #333; padding: 4px 8px; border-radius: 4px; }}
        .section-header h3 {{ color: var(--accent); margin: 0; font-size: 1.3em; }}
        .top-link {{ margin-left: auto; color: #666; text-decoration: none; font-size: 0.8em; }}
        pre.content {{ white-space: pre-wrap; overflow-wrap: anywhere; font-family: 'Consolas', monospace; font-size: 0.9em; background: #15151a; padding: 20px; border-radius: 6px; border: 1px solid #2a2a2a; color: #ccc; line-height: 1.15; }}
        #report-view.nowrap pre.content {{ white-space: pre; overflow-wrap: normal; overflow-x: auto; }}

        /* Findings-only filter */
        body.findings-only .report-section:not(.has-finding) {{ display: none; }}
        body.findings-only .toc-link:not(.has-finding) {{ display: none; }}
        body.findings-only li.category-group:not(.cat-has-finding) {{ display: none; }}

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
            <label class=\"nav-toggle\"><input type=\"checkbox\" id=\"findings-only\" onchange=\"toggleFindingsOnly(this)\"> Findings only</label>
            <label class=\"nav-toggle\"><input type=\"checkbox\" id=\"wrap-toggle\" checked onchange=\"toggleWrap(this)\"> Wrap lines</label>
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
            <div class=\"meta-info\">
                {user_badge}{os_badge}
                <span class=\"hdr-badge\">{hostname}</span>
                <span>{timestamp}</span>
            </div>
        </header>
        <div id=\"report-view\" class=\"view active\">
            <div id=\"findings-bar\">
                <span class=\"fb-label\">Findings</span>
                {findings_summary}
                <span class=\"legend\">
                    <span><span class=\"lg-dot crit\"></span>critical</span>
                    <span><span class=\"lg-dot high\"></span>high</span>
                </span>
            </div>
            <div class=\"report-body\">
                {content}
            </div>
        </div>
        <div id=\"terminal-view\" class=\"view\">
            <pre id=\"term-content\"></pre>
        </div>
        <div id=\"loading\">Loading...</div>
    </main>
    <script>
        const TERMINAL_FILE = '{json_file}';
        const REPORT_ID = '{report_id}';
        const READ_KEY = 'pp_read_' + REPORT_ID;
        let terminalLoaded = false;

        function expandAll(open) {{ document.querySelectorAll('details').forEach(el => el.open = open); }}

        function switchView(viewName) {{
            document.querySelectorAll('.view').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tabs button').forEach(el => el.classList.remove('active'));
            document.getElementById(viewName + '-view').classList.add('active');
            const btns = document.querySelectorAll('.tabs button');
            if (viewName === 'report') btns[0].classList.add('active'); else btns[1].classList.add('active');
            if (viewName === 'terminal' && !terminalLoaded) {{ loadTerminal(); }}
        }}

        // --- Terminal view: render the whole output at once so Ctrl-F works ---
        async function loadTerminal() {{
            const loader = document.getElementById('loading');
            loader.style.display = 'block';
            try {{
                const res = await fetch(TERMINAL_FILE);
                if (!res.ok) throw new Error("HTTP " + res.status);
                const data = await res.json();
                document.getElementById('term-content').innerHTML = data.chunks.join("\\n");
                terminalLoaded = true;
            }} catch (e) {{
                document.getElementById('term-content').innerText = "Load failed: " + e;
            }} finally {{
                loader.style.display = 'none';
            }}
        }}

        // --- Wrap toggle ---
        function toggleWrap(el) {{
            document.getElementById('report-view').classList.toggle('nowrap', !el.checked);
        }}

        // --- Findings-only filter ---
        function toggleFindingsOnly(el) {{
            document.body.classList.toggle('findings-only', el.checked);
        }}

        // --- Jump between findings of a given level ---
        const jumpState = {{ critical: -1, high: -1 }};
        function jumpFinding(level) {{
            const list = Array.from(document.querySelectorAll('.report-section.has-' + level));
            if (!list.length) return;
            jumpState[level] = (jumpState[level] + 1) % list.length;
            list[jumpState[level]].scrollIntoView({{ behavior: 'smooth', block: 'start' }});
        }}

        // --- Persisted "mark as read" dots (localStorage per report) ---
        function loadRead() {{
            try {{ return new Set(JSON.parse(localStorage.getItem(READ_KEY) || '[]')); }}
            catch (e) {{ return new Set(); }}
        }}
        function saveRead(set) {{
            try {{ localStorage.setItem(READ_KEY, JSON.stringify(Array.from(set))); }} catch (e) {{}}
        }}
        function toggleRead(el, event) {{
            event.preventDefault();
            event.stopPropagation();
            el.classList.toggle('read');
            const set = loadRead();
            const sid = el.dataset.sid;
            if (el.classList.contains('read')) set.add(sid); else set.delete(sid);
            saveRead(set);
        }}

        // --- Scrollspy: highlight the current section in the TOC ---
        function initScrollSpy() {{
            const links = {{}};
            document.querySelectorAll('nav a[href^="#"]').forEach(a => {{
                links[a.getAttribute('href').slice(1)] = a;
            }});
            const obs = new IntersectionObserver((entries) => {{
                entries.forEach(e => {{
                    if (e.isIntersecting) {{
                        document.querySelectorAll('nav a.active').forEach(a => a.classList.remove('active'));
                        const l = links[e.target.id];
                        if (l) {{ l.classList.add('active'); l.scrollIntoView({{ block: 'nearest' }}); }}
                    }}
                }});
            }}, {{ root: document.getElementById('report-view'), rootMargin: '0px 0px -75% 0px', threshold: 0 }});
            document.querySelectorAll('.report-section').forEach(s => obs.observe(s));
        }}

        // --- Init ---
        document.addEventListener('DOMContentLoaded', () => {{
            const set = loadRead();
            document.querySelectorAll('.toc-finding-dot').forEach(d => {{
                if (set.has(d.dataset.sid)) d.classList.add('read');
            }});
            initScrollSpy();
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
