# ParsingPeas TODO

Tracker for planned improvements and features.

## 🔴 High Priority

### Improve WinPEAS Categorization
- [ ] Review and expand WinPEAS-specific section keywords
- [ ] Better mapping for Windows-specific checks (Registry, Services, UAC, etc.)
- [ ] Test against multiple WinPEAS outputs to validate categories
- [ ] Consider separate category mappings for LinPEAS vs WinPEAS

### Fix WinPEAS Header Encoding
- [x] ~~Added ANSI color pattern detection (cyan + green)~~ ✅
- [ ] Handle edge cases where headers don't follow standard color scheme
- [ ] Test with WinPEAS output from different PowerShell/CMD encodings
- [ ] Add fallback detection for headers without ANSI codes

## 🟡 Medium Priority

### Add Search Functionality
- [ ] Implement client-side search in HTML report
  - [ ] Search across all sections
  - [ ] Highlight matches
  - [ ] Filter sections by search term
  - [ ] Search within terminal view
- [ ] Add regex support for advanced queries
- [ ] Search history/recent searches

### User Context Display
- [ ] Extract username from scan output (e.g., "My user", "whoami", "Current User")
- [ ] Display user badge at top-right of report header
- [ ] Show privilege level (Admin/High Integrity vs Standard User)
- [ ] Color-code user badge based on privilege level:
  - Red = SYSTEM/root
  - Yellow = Administrator/sudo
  - Green = Standard user

### Improve File Naming
- [ ] Current format: `report_hostname_20260201_224952.html`
- [ ] New format ideas:
  - `hostname_user_20260201-2249_winpeas.html`
  - `hostname-ADMIN_2026-02-01_22h49m.html`
  - `[hostname]_[user]_[date]_[tool].html`
- [ ] Make format configurable via CLI argument
- [ ] Add metadata to filename (e.g., critical findings count)

## 🟢 Low Priority / Nice-to-Have

### Additional Features
- [ ] Export findings as JSON/CSV
- [ ] Compare mode: diff two reports side-by-side
- [ ] Timeline view: sort findings by timestamp
- [ ] Generate executive summary (auto-summary of top findings)
- [ ] Dark/Light theme toggle
- [ ] Bookmarking system for important sections

### Performance
- [ ] Optimize large file parsing (>10MB outputs)
- [ ] Lazy load terminal view chunks on demand (already implemented)
- [ ] Add progress indicator during parsing

### LinPEAS Improvements
- [ ] Better detection of SUID/SGID findings
- [ ] Improve cron job parsing
- [ ] Enhanced password/credential detection

## 📝 Documentation
- [ ] Add usage examples to README
- [ ] Create demo screenshots
- [ ] Document color coding system
- [ ] Add troubleshooting guide for encoding issues

## 🐛 Known Issues
- [ ] Some WinPEAS sections may still be miscategorized
- [ ] Terminal view scrolling performance on very large files
- [ ] HTML report doesn't work offline if CDN resources are needed (currently none)

---

**Legend:**
- 🔴 High Priority - Critical for usability
- 🟡 Medium Priority - Important but not blocking
- 🟢 Low Priority - Nice-to-have enhancements
- ✅ Completed
