"""CLI entry point: python3 -m pdf_analyzer <command> [args]"""

import json
import os
import sys


def cmd_scan(args):
    from .scanner import analyze, print_report

    if not args or args[0].startswith("--"):
        print("Usage: python3 -m pdf_analyzer scan <pdf_file> [--json] [--password PASSWORD]")
        sys.exit(1)

    pdf_path = args[0]
    output_json = "--json" in args
    password = None
    if "--password" in args:
        idx = args.index("--password")
        if idx + 1 < len(args):
            password = args[idx + 1]

    if not os.path.isfile(pdf_path):
        print(f"Error: File not found: {pdf_path}")
        sys.exit(1)

    report = analyze(pdf_path, password=password)

    if output_json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)


def cmd_clean(args):
    from .cleaner import clean_pdf, print_report

    if not args or args[0].startswith("--"):
        print("Usage: python3 -m pdf_analyzer clean <input.pdf> [output.pdf] [--json] [--password PASSWORD] [--balanced] [--no-defang]")
        print()
        print("If no output path is given, writes to <input>_clean.pdf")
        sys.exit(1)

    output_json = "--json" in args

    password = None
    if "--password" in args:
        idx = args.index("--password")
        if idx + 1 < len(args):
            password = args[idx + 1]

    skip_next = False
    positional = []
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a == "--password":
            skip_next = True
            continue
        if a.startswith("--"):
            continue
        positional.append(a)

    input_path = positional[0]
    if len(positional) >= 2:
        output_path = positional[1]
    else:
        base, ext = os.path.splitext(input_path)
        output_path = f"{base}_clean{ext}"

    if not os.path.isfile(input_path):
        print(f"Error: File not found: {input_path}")
        sys.exit(1)

    level = "balanced" if "--balanced" in args else "strict"
    defang_urls = "--no-defang" not in args

    report = clean_pdf(input_path, output_path, password=password, level=level, defang_urls=defang_urls)

    if output_json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)


def cmd_vt(args):
    from .vt import get_api_key, compute_sha256, lookup_hash, print_report

    if not args or args[0].startswith("--"):
        print("Usage: python3 -m pdf_analyzer vt <pdf_file> [--json]")
        sys.exit(1)

    pdf_path = args[0]
    output_json = "--json" in args

    if not os.path.isfile(pdf_path):
        print(f"Error: File not found: {pdf_path}")
        sys.exit(1)

    api_key = get_api_key()
    if not api_key:
        msg = {
            "error": "No VirusTotal API key configured",
            "help": "Set VT_API_KEY env var, add to config.json, or store via: pass insert pdf-analyzer/virustotal-api-key",
        }
        if output_json:
            print(json.dumps(msg, indent=2))
        else:
            print(f"Error: {msg['error']}")
            print(f"Help:  {msg['help']}")
        sys.exit(1)

    sha256 = compute_sha256(pdf_path)
    result = lookup_hash(sha256, api_key)

    if output_json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result)


COMMANDS = {
    "scan": cmd_scan,
    "clean": cmd_clean,
    "vt": cmd_vt,
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print("Usage: python3 -m pdf_analyzer <command> [args]")
        print()
        print("Commands:")
        print("  scan   <file>                Analyze a PDF (layers 1-5)")
        print("  clean  <file> [output]       Strip malicious elements")
        print("  vt     <file>                VirusTotal hash lookup (layer 6)")
        sys.exit(1)

    command = sys.argv[1]
    COMMANDS[command](sys.argv[2:])


if __name__ == "__main__":
    main()
