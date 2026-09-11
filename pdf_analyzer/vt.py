"""
VirusTotal integration for PDF hash lookups.
Layer 6: Threat Intelligence.

Looks up the SHA256 hash of a PDF - never uploads the file itself.
Requires a VirusTotal API key via environment variable, keystore, or config.
"""

import hashlib
import json
import os
import urllib.request
import urllib.error


def get_api_key() -> str | None:
    """Resolve VT API key from multiple sources, in priority order."""

    key = os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")
    if key:
        return key

    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
    if os.path.isfile(config_path):
        try:
            with open(config_path) as f:
                config = json.load(f)
            key = config.get("virustotal", {}).get("api_key")
            if key and key != "YOUR_API_KEY_HERE":
                return key
        except Exception:
            pass

    try:
        import subprocess
        result = subprocess.run(
            ["pass", "show", "pdf-analyzer/virustotal-api-key"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass

    return None


def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def lookup_hash(sha256: str, api_key: str) -> dict:
    """Look up a file hash on VirusTotal. Never uploads the file."""
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + undetected + stats.get("harmless", 0)

            flagged_by = []
            for vendor, detail in results.items():
                if detail.get("category") in ("malicious", "suspicious"):
                    flagged_by.append({
                        "vendor": vendor,
                        "result": detail.get("result", "unknown"),
                        "category": detail.get("category"),
                    })

            detections = malicious + suspicious
            if detections >= 16:
                score = 4
                level = "HIGH"
            elif detections >= 6:
                score = 3
                level = "MEDIUM"
            elif detections >= 1:
                score = 2
                level = "LOW"
            else:
                score = 0
                level = "CLEAN"

            return {
                "found": True,
                "sha256": sha256,
                "detections": detections,
                "total_vendors": total,
                "malicious": malicious,
                "suspicious": suspicious,
                "detection_level": level,
                "score_contribution": score,
                "flagged_by": flagged_by[:20],
                "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
                "tags": attrs.get("tags", []),
                "type_description": attrs.get("type_description", ""),
                "names": attrs.get("names", [])[:5],
            }

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {
                "found": False,
                "sha256": sha256,
                "detections": 0,
                "total_vendors": 0,
                "score_contribution": 0,
                "detection_level": "UNKNOWN",
                "message": "Hash not found in VirusTotal database",
                "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
            }
        elif e.code == 429:
            return {
                "found": False,
                "error": "Rate limited - VirusTotal free tier allows 4 requests/minute",
                "sha256": sha256,
            }
        else:
            return {
                "found": False,
                "error": f"VirusTotal API error: HTTP {e.code}",
                "sha256": sha256,
            }
    except Exception as e:
        return {
            "found": False,
            "error": f"Request failed: {str(e)}",
            "sha256": sha256,
        }


def print_report(result: dict):
    print(f"\n{'='*60}")
    print(f"  VIRUSTOTAL - Layer 6 Threat Intelligence")
    print(f"{'='*60}")
    print(f"  SHA256: {result['sha256']}")

    if result.get("error"):
        print(f"  Error:  {result['error']}")
        print(f"{'='*60}")
        return

    if not result["found"]:
        print(f"  Status: Not found in VirusTotal database")
        print(f"  Note:   This doesn't mean it's safe - it may be new or targeted")
        print(f"  Link:   {result['permalink']}")
        print(f"{'='*60}")
        return

    print(f"  Status: {'DETECTED' if result['detections'] > 0 else 'CLEAN'}")
    print(f"  Detections: {result['detections']}/{result['total_vendors']} vendors")
    print(f"  Level:  {result['detection_level']}")
    print(f"  Score:  +{result['score_contribution']}")

    if result.get("type_description"):
        print(f"  Type:   {result['type_description']}")

    if result.get("tags"):
        print(f"  Tags:   {', '.join(result['tags'][:10])}")

    if result.get("names"):
        print(f"  Known as: {', '.join(result['names'])}")

    print(f"  Link:   {result['permalink']}")

    if result.get("flagged_by"):
        print(f"\n  VENDOR DETECTIONS")
        for v in result["flagged_by"]:
            print(f"    {v['vendor']}: {v['result']} ({v['category']})")

    print(f"{'='*60}")
