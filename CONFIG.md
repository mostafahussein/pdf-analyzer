# Configuration

Layers 1–5 work immediately with no configuration. This guide covers optional threat intelligence setup.

## VirusTotal (Layer 6)

VirusTotal looks up the PDF's SHA256 hash to check if it's a known threat. The file is **never uploaded** -- only its hash is sent.

### Get an API key

1. Sign up at [virustotal.com](https://www.virustotal.com/gui/join-us)
2. Go to your profile → API key

Free tier: 4 requests/minute, 1,000/day.

### Configure the key

Pick **one** method (checked in this order):

#### Option 1: Environment variable (simplest)

```bash
export VT_API_KEY="your-key-here"
```

Add to your shell profile (`~/.bashrc`, `~/.zshrc`) to persist.

#### Option 2: Config file

```bash
cp config.template.json config.json
# Edit config.json and replace YOUR_API_KEY_HERE
```

**Never commit `config.json`** -- it's in `.gitignore`.

#### Option 3: Password store (most secure)

```bash
pass insert pdf-analyzer/virustotal-api-key
```

Confirm it works:

```bash
python3 -c "from pdf_analyzer.vt import get_api_key; print(bool(get_api_key()))"
```

## Verify

```bash
# Should print True if any method is configured
python3 -c "from pdf_analyzer.vt import get_api_key; print(bool(get_api_key()))"
```

## Risk threshold tuning

Edit `config.json` to adjust score boundaries:

```json
{
  "risk_thresholds": {
    "low": 3,
    "medium": 6,
    "high": 12,
    "critical": 13
  }
}
```

Tune against your own PDF traffic to reduce false positives.
