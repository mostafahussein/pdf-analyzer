# PDF Analyzer

> Multi-layered malicious PDF analysis and cleaning. Static analysis, threat intelligence, and sanitization for suspicious PDFs.

## What it Does

PDF Analyzer dissects suspicious PDFs through six layers of static analysis and threat intelligence. It never renders a PDF, never executes JavaScript, and never opens embedded files. You get a risk score with the evidence behind it and IOCs you can feed into your detection tools.

**Core features:**
- Safe PDF parsing. Files are read as raw bytes, never rendered or executed.
- Six analysis layers: structure, actions, JavaScript, embedded content, obfuscation, threat intelligence
- Cleaning/sanitization: strip malicious elements and output a safe copy
- VirusTotal hash reputation lookup (never uploads the file)
- IOC extraction: hashes, URLs, embedded filenames

**Built for:**
- SOC analysts triaging suspicious PDF attachments
- Malware analysts doing initial PDF triage
- Incident responders extracting IOCs from weaponized PDFs
- Security teams that need a quick safe/suspicious/malicious verdict

---

## Quick Start

Layers 1 through 5 need no configuration and no network access. Clone, and analyse a PDF immediately.

```bash
# Install as a Claude Code skill
mkdir -p .claude/skills
cp SKILL.md .claude/skills/pdf-analyzer.md

pip install -r requirements.txt

# Optional: only needed for VirusTotal lookups
cp config.template.json config.json
```

Then:

```bash
claude /pdf-analyzer      # or /pdf-analyze, or /pdf-clean
```

Upload a `.pdf` file or provide a path to one.

Everything beyond the offline baseline is configured in **[CONFIG.md](CONFIG.md)**.

---

## What Each Layer Adds

```
no config      →  Layers 1-5   static analysis, fully offline
+ VirusTotal   →  Layer 6      hash reputation lookup
```

### Layer 1: Structure Parsing
PDF version, page count, object count, metadata, file size, cross-reference tables, trailers.

### Layer 2: Action Detection
`/OpenAction`, `/AA`, `/Launch`, `/URI`, `/SubmitForm`, `/ImportData`, remote GoTo (`/GoToR`, `/GoToE`).

### Layer 3: JavaScript Detection
`/JS`, `/JavaScript`, named JavaScript in catalog, obfuscated JS (`eval`, `unescape`, hex encoding, `String.fromCharCode`).

### Layer 4: Embedded Content
`/EmbeddedFiles`, executable attachments (`.exe`, `.bat`, `.ps1`, `.dll`, `.scr`, `.hta`, etc.), `/RichMedia`, `/AcroForm` + `/XFA` forms.

### Layer 5: Obfuscation Detection
Deep `/FlateDecode` filter chains (3+ stages), hex-encoded PDF names, object streams, non-standard encryption handlers.

### Layer 6: Threat Intelligence (VirusTotal)
SHA256 hash lookup -- never uploads the file. Detection ratio, vendor flags, known malware identification. See [CONFIG.md](CONFIG.md) for setup.

### Cleaning / Sanitization
Strip `/OpenAction`, `/AA`, JavaScript, `/Launch`, `/SubmitForm`, `/ImportData`, `/URI` actions, embedded files, XFA forms, and dangerous URI schemes. Powered by [pdf-defang](https://github.com/kovetz-PDF/pdf-defang) for proper PDF parsing -- preserves document layout and handles encrypted PDFs.

---

## Risk Scoring

| Score | Verdict  | Action |
|-------|----------|--------|
| 0-3   | LOW      | Likely legitimate |
| 4-6   | MEDIUM   | Suspicious -- analyst review |
| 7-12  | HIGH     | Probable malicious -- block and investigate |
| 13+   | CRITICAL | Confirmed malicious -- block immediately |

Sample factors: `/OpenAction` +3, `/Launch` +4, JavaScript +3, embedded executable +4, obfuscated JS +2, 16+ VirusTotal detections +4. The full scoring matrix is in [SKILL.md](SKILL.md).

Thresholds are tunable in `config.json`. Tune them against your own PDF traffic.

---

## Example Session

```
You: /pdf-analyzer

Claude: PDF Analyzer ready. Upload a suspicious PDF file or provide a path to one.

        Commands:
          analyze <file>  -- scan and report (default)
          clean <file>    -- strip malicious elements and output a safe copy

You: [provides suspicious.pdf]

Claude:   PDF ANALYSIS REPORT
        File:    suspicious.pdf
        SHA256:  a1b2c3d4...
        Size:    24,832 bytes
        Pages:   1

        RISK ASSESSMENT
        Score:      9/13+
        Verdict:    HIGH
        Confidence: HIGH
        Action:     Probable malicious -- block, investigate, extract IOCs

        EVIDENCE
          [Layer 2] (+3) /OpenAction -- Auto-execute on open
          [Layer 3] (+3) /JavaScript -- JavaScript execution in action
          [Layer 3] (+2) Suspicious JS functions -- eval() found
          [Layer 5] (+1) Object streams -- Objects hidden inside streams

        VIRUSTOTAL
          Detections: 8/70 vendors
          Level: MEDIUM (+3)

        IOCs
          SHA256: a1b2c3d4...
          URLs: hxxp://malicious-site[.]com
```

---

## Safety Guarantees

- **Never renders** the PDF
- **Never executes** JavaScript or actions
- **Never opens** embedded files
- **Never visits** URLs found in the PDF
- **Never uploads** files to VirusTotal (hash-only lookup)

All analysis is static parsing, regex pattern matching, and hash-based API lookups.

---

## Troubleshooting

### "VirusTotal API key not configured"

Store it and retry:

```bash
export VT_API_KEY="your-key-here"
```

Or use `config.json` or `pass`. See [CONFIG.md](CONFIG.md) for all methods.

Confirm it resolves:

```bash
python3 -c "from pdf_analyzer.vt import get_api_key; print(bool(get_api_key()))"
```

### Rate limits

VirusTotal free tier allows 4 requests per minute and 1,000 per day. Wait between analyses or upgrade your API key.

### "This doesn't look like a PDF"

The file should start with `%PDF-`. Export or download the original PDF rather than a preview or HTML version.

---

## FAQ

**Will this open or render the PDF?**
No. Static analysis and hash lookups only. The PDF is read as raw bytes.

**What works with no API keys at all?**
Layers 1 through 5. Structure parsing, action detection, JavaScript detection, embedded content, and obfuscation detection are entirely local.

**Can I clean a PDF without analyzing it first?**
The cleaner always scans first so you can see what will be removed before and after.

**What if the PDF is legitimate?**
It scores low and the analyzer says so. Use your judgment regardless.

**Can I change the risk thresholds?**
Yes, `risk_thresholds` in `config.json`. See [CONFIG.md](CONFIG.md).

---

## Files

| File | Purpose |
|------|---------|
| `pdf_analyzer/` | Python package |
| `pdf_analyzer/scanner.py` | Static analyzer (Layers 1-5) |
| `pdf_analyzer/cleaner.py` | Sanitizer - strips malicious elements |
| `pdf_analyzer/vt.py` | VirusTotal integration (Layer 6) |
| `pdf_analyzer/__main__.py` | CLI entry point |
| `SKILL.md` | Skill definition for Claude Code |
| `skill.json` | Skill metadata, commands, and version |
| `requirements.txt` | Python dependencies |
| `config.template.json` | Configuration template |
| `CONFIG.md` | Setup guide for optional features |

---

## Contributing

Bug reports and pull requests welcome. Useful directions: more threat intelligence sources (URLScan, MalwareBazaar), deeper obfuscation detection, XFA form analysis, and encrypted PDF handling.

---

## License

MIT
