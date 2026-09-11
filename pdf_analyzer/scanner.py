"""
Layers 1-5: Structure, Actions, JavaScript, Embedded Content, Obfuscation.
Uses pdf-defang for layers 2-4 (proper PDF parsing). Never executes, renders,
or opens anything.
"""

import hashlib
import json
import os
import re
import sys

from pdf_defang import scan, ScanReport


def compute_hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def extract_pdf_version(raw: str) -> str:
    m = re.match(r"%PDF-(\d+\.\d+)", raw[:20])
    return m.group(1) if m else "unknown"


def count_objects(raw: str) -> int:
    return len(re.findall(r"\d+\s+\d+\s+obj", raw))


def count_pages(raw: str) -> int:
    m = re.search(r"/Type\s*/Pages.*?/Count\s+(\d+)", raw, re.DOTALL)
    if m:
        return int(m.group(1))
    return len(re.findall(r"/Type\s*/Page(?!\s*s)", raw))


def extract_metadata(raw: str) -> dict:
    meta = {}
    for key in ["Author", "Creator", "Producer", "Title", "Subject", "CreationDate", "ModDate"]:
        m = re.search(rf"/{key}\s*\(([^)]*)\)", raw)
        if m:
            meta[key] = m.group(1)
        else:
            m = re.search(rf"/{key}\s*<([^>]*)>", raw)
            if m:
                meta[key] = m.group(1)
    return meta


# ---------------------------------------------------------------------------
# Layer 1: Structure
# ---------------------------------------------------------------------------

def analyze_structure(raw: str, file_size: int) -> dict:
    return {
        "pdf_version": extract_pdf_version(raw),
        "pages": count_pages(raw),
        "objects": count_objects(raw),
        "file_size": file_size,
        "metadata": extract_metadata(raw),
        "streams": len(re.findall(r"\bstream\b", raw)),
        "has_xref": bool(re.search(r"\bxref\b", raw)),
        "has_trailer": bool(re.search(r"\btrailer\b", raw)),
    }


# ---------------------------------------------------------------------------
# Layers 2-4: Actions, JavaScript, Embedded Content (via pdf-defang)
# ---------------------------------------------------------------------------

def findings_from_scan(scan_report: ScanReport) -> list:
    """Convert pdf-defang ScanReport into scored findings."""
    findings = []

    if scan_report.has_open_action:
        findings.append({
            "layer": 2,
            "indicator": "/OpenAction",
            "score": 3,
            "description": "Auto-execute on open",
        })

    if scan_report.has_document_aa:
        findings.append({
            "layer": 2,
            "indicator": "/AA (document)",
            "score": 3,
            "description": "Document-level Additional Actions",
        })

    if scan_report.pages_with_aa > 0:
        findings.append({
            "layer": 2,
            "indicator": "/AA (pages)",
            "score": 3,
            "description": f"Page-level Additional Actions ({scan_report.pages_with_aa} page(s))",
        })

    action_scores = {
        "Launch": ("Layer 2", "/Launch", 4, "Launch external application"),
        "SubmitForm": ("Layer 2", "/SubmitForm", 3, "Exfiltrate form data to external URL"),
        "ImportData": ("Layer 2", "/ImportData", 2, "Import external data file"),
        "GoToR": ("Layer 2", "/GoToR", 2, "Remote GoTo action"),
        "GoToE": ("Layer 2", "/GoToE", 2, "Embedded GoTo action"),
        "JavaScript": ("Layer 3", "/JavaScript", 3, "JavaScript execution in annotation"),
        "Rendition": ("Layer 2", "/Rendition", 2, "Media rendition action"),
        "Movie": ("Layer 2", "/Movie", 1, "Movie playback action"),
        "Sound": ("Layer 2", "/Sound", 1, "Sound playback action"),
    }

    for action_type in scan_report.annotation_action_types:
        if action_type in action_scores:
            layer_name, indicator, score, desc = action_scores[action_type]
            layer_num = int(layer_name.split()[1])
            findings.append({
                "layer": layer_num,
                "indicator": indicator,
                "score": score,
                "description": desc,
            })

    if scan_report.has_javascript:
        findings.append({
            "layer": 3,
            "indicator": "Named JavaScript",
            "score": 3,
            "description": f"Named JavaScript entries in catalog ({scan_report.javascript_in_names})",
        })

    if scan_report.annotations_with_js > 0:
        findings.append({
            "layer": 3,
            "indicator": "Annotation /JS",
            "score": 2,
            "description": f"JavaScript in annotations ({scan_report.annotations_with_js})",
        })

    if scan_report.dangerous_uris > 0:
        real_schemes = [s for s in scan_report.dangerous_uri_schemes if s not in ("hxxps", "hxxp", "fxp")]
        if real_schemes:
            schemes = ", ".join(real_schemes)
            findings.append({
                "layer": 2,
                "indicator": "Dangerous URIs",
                "score": 2,
                "description": f"Dangerous URI schemes ({scan_report.dangerous_uris}): {schemes}",
            })

    if scan_report.has_embedded_files:
        findings.append({
            "layer": 4,
            "indicator": "/EmbeddedFiles",
            "score": 2,
            "description": f"Embedded file(s) ({scan_report.embedded_files_count})",
        })

    if scan_report.has_xfa_form:
        findings.append({
            "layer": 4,
            "indicator": "/AcroForm + /XFA",
            "score": 2,
            "description": "XFA form detected (large attack surface)",
        })

    return findings


# ---------------------------------------------------------------------------
# Layer 3 supplement: JavaScript in action objects (not covered by pdf-defang)
# ---------------------------------------------------------------------------

def detect_javascript_in_actions(raw: str, scan_report: ScanReport) -> list:
    """Catch JavaScript in action objects that pdf-defang misses."""
    findings = []

    if scan_report.has_javascript:
        return findings

    if re.search(r"/S\s*/JavaScript", raw):
        findings.append({
            "layer": 3,
            "indicator": "/S /JavaScript",
            "score": 3,
            "description": "JavaScript action in object",
        })
    elif re.search(r"/JS\s*[\(<]", raw):
        findings.append({
            "layer": 3,
            "indicator": "/JS",
            "score": 3,
            "description": "JavaScript payload in object",
        })

    js_blocks = re.findall(r"/JS\s*\(([^)]*)\)", raw)
    js_blocks += re.findall(r"/JS\s*<([^>]*)>", raw)
    js_content = " ".join(js_blocks).lower()

    if js_content:
        if "eval(" in js_content or "unescape(" in js_content:
            findings.append({
                "layer": 3,
                "indicator": "Suspicious JS functions",
                "score": 2,
                "description": "eval() or unescape() found in JavaScript",
            })

        if re.search(r"(\\x[0-9a-f]{2}){10,}", js_content) or re.search(r"String\.fromCharCode", js_content, re.IGNORECASE):
            findings.append({
                "layer": 3,
                "indicator": "Obfuscated JavaScript",
                "score": 2,
                "description": "Obfuscated JS payload (hex encoding or charCode)",
            })

    return findings


# ---------------------------------------------------------------------------
# Layer 5: Obfuscation Detection
# ---------------------------------------------------------------------------

def detect_obfuscation(raw: str) -> list:
    findings = []

    filter_chains = re.findall(r"/Filter\s*\[([^\]]+)\]", raw)
    for chain in filter_chains:
        decode_count = chain.count("Decode")
        if decode_count >= 3:
            findings.append({
                "layer": 5,
                "indicator": "Deep filter chain",
                "score": 2,
                "description": f"Filter chain with {decode_count} decode stages",
            })
            break

    hex_names = re.findall(r"/((?:#[0-9A-Fa-f]{2}){3,})", raw)
    if hex_names:
        decoded_samples = []
        for h in hex_names[:3]:
            try:
                decoded = re.sub(r"#([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), h)
                decoded_samples.append(decoded)
            except Exception:
                decoded_samples.append(h)
        findings.append({
            "layer": 5,
            "indicator": "Hex-encoded names",
            "score": 2,
            "description": f"Obfuscated PDF names found: {', '.join(decoded_samples)}",
        })

    if re.search(r"/Type\s*/ObjStm", raw):
        findings.append({
            "layer": 5,
            "indicator": "Object streams",
            "score": 1,
            "description": "Objects hidden inside object streams",
        })

    if re.search(r"/Encrypt", raw):
        if not re.search(r"/Filter\s*/Standard", raw):
            findings.append({
                "layer": 5,
                "indicator": "Non-standard encryption",
                "score": 2,
                "description": "Encryption with non-standard handler",
            })

    return findings


# ---------------------------------------------------------------------------
# Extract URLs and IOCs
# ---------------------------------------------------------------------------

def extract_urls(raw: str) -> list:
    urls = set()
    for m in re.finditer(r"/URI\s*\(([^)]+)\)", raw):
        urls.add(m.group(1))
    for m in re.finditer(r"/URI\s*<([^>]+)>", raw):
        try:
            decoded = bytes.fromhex(m.group(1)).decode("utf-8", errors="replace")
            urls.add(decoded)
        except Exception:
            pass
    for m in re.finditer(r"/F\s*\(https?://[^)]+\)", raw):
        urls.add(m.group(0).split("(")[1].rstrip(")"))
    return sorted(urls)


def extract_embedded_filenames(raw: str) -> list:
    names = set()
    for m in re.finditer(r"/F\s*\(([^)]+)\)", raw):
        names.add(m.group(1))
    for m in re.finditer(r"/UF\s*\(([^)]+)\)", raw):
        names.add(m.group(1))
    return sorted(names)


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def compute_risk(findings: list) -> dict:
    total = sum(f["score"] for f in findings)

    if total >= 13:
        verdict = "CRITICAL"
        action = "Confirmed malicious -- block immediately"
    elif total >= 7:
        verdict = "HIGH"
        action = "Probable malicious -- block, investigate, extract IOCs"
    elif total >= 4:
        verdict = "MEDIUM"
        action = "Suspicious -- analyst review recommended"
    else:
        verdict = "LOW"
        action = "Likely legitimate"

    confidence = "HIGH" if total >= 7 else ("MEDIUM" if total >= 4 else "LOW")

    return {
        "score": total,
        "verdict": verdict,
        "confidence": confidence,
        "action": action,
    }


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyze(pdf_path: str, password: str | None = None) -> dict:
    with open(pdf_path, "rb") as f:
        data = f.read()

    hashes = compute_hashes(data)
    raw = data.decode("latin-1")

    structure = analyze_structure(raw, len(data))

    scan_report = scan(pdf_path, password=password)
    findings = findings_from_scan(scan_report)
    findings.extend(detect_javascript_in_actions(raw, scan_report))
    findings.extend(detect_obfuscation(raw))

    risk = compute_risk(findings)

    urls = extract_urls(raw)
    embedded_files = extract_embedded_filenames(raw)

    return {
        "file": os.path.basename(pdf_path),
        "hashes": hashes,
        "structure": structure,
        "findings": findings,
        "risk": risk,
        "iocs": {
            "sha256": hashes["sha256"],
            "md5": hashes["md5"],
            "urls": urls,
            "embedded_filenames": embedded_files,
        },
    }


def print_report(report: dict):
    r = report
    s = r["structure"]
    risk = r["risk"]

    print(f"\n{'='*60}")
    print(f"  PDF ANALYZER -- Analysis Report")
    print(f"{'='*60}")
    print(f"  File:    {r['file']}")
    print(f"  SHA256:  {r['hashes']['sha256']}")
    print(f"  MD5:     {r['hashes']['md5']}")
    print(f"  Size:    {s['file_size']} bytes")
    print(f"  Pages:   {s['pages']}")
    print(f"  Objects: {s['objects']}")
    print(f"  Version: PDF {s['pdf_version']}")
    print()

    if s["metadata"]:
        print("  Metadata:")
        for k, v in s["metadata"].items():
            print(f"    {k}: {v}")
        print()

    print(f"  RISK ASSESSMENT")
    print(f"  Score:      {risk['score']}/13+")
    print(f"  Verdict:    {risk['verdict']}")
    print(f"  Confidence: {risk['confidence']}")
    print(f"  Action:     {risk['action']}")
    print()

    if r["findings"]:
        print(f"  EVIDENCE")
        for f in r["findings"]:
            print(f"    [Layer {f['layer']}] (+{f['score']}) {f['indicator']}")
            print(f"             {f['description']}")
        print()
    else:
        print("  No suspicious indicators found.")
        print()

    if r["iocs"]["urls"]:
        print(f"  URLs FOUND (do NOT visit)")
        for u in r["iocs"]["urls"]:
            print(f"    {u}")
        print()

    if r["iocs"]["embedded_filenames"]:
        print(f"  EMBEDDED FILES")
        for f in r["iocs"]["embedded_filenames"]:
            print(f"    {f}")
        print()

    print(f"{'='*60}")
