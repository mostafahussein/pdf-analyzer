"""
PDF cleaner/sanitizer.
Strips malicious elements from a PDF and writes a clean copy.
Uses pdf-defang for proper PDF parsing and sanitization.
"""

import json
import os
import re
import shutil

import pikepdf
from pdf_defang import sanitize, SanitizeReport


def defang_url(url: str, bracket_dots: bool = True) -> str:
    """Defang a URL so it's visible but not clickable.

    Set bracket_dots=False for content streams where the font
    may not have glyphs for [ and ] characters.
    """
    url = re.sub(r"^https://", "hxxps://", url)
    url = re.sub(r"^http://", "hxxp://", url)
    url = re.sub(r"^ftp://", "fxp://", url)
    if bracket_dots:
        parts = url.split("/", 3)
        if len(parts) >= 3:
            parts[2] = parts[2].replace(".", "[.]")
            url = "/".join(parts)
    return url


def _neutralize_annotation(annot: pikepdf.Dictionary) -> bool:
    """Neutralize a single URI link annotation. Returns True if modified."""
    try:
        if "/A" in annot:
            action = annot["/A"]
            if isinstance(action, pikepdf.Dictionary) and str(action.get("/S", "")) == "/URI":
                url = str(action.get("/URI", ""))
                if url:
                    annot[pikepdf.Name("/Contents")] = pikepdf.String(defang_url(url))
                del annot["/A"]
                if "/Subtype" in annot and str(annot["/Subtype"]) == "/Link":
                    annot["/Subtype"] = pikepdf.Name("/Text")
                if "/Rect" in annot:
                    del annot["/Rect"]
                return True
    except Exception:
        pass
    return False


def _defang_content_streams(pdf: pikepdf.Pdf) -> None:
    """Defang URLs in page content streams and reset link colors."""
    for page in pdf.pages:
        try:
            if "/Contents" not in page:
                continue
            contents = page.Contents
            if isinstance(contents, pikepdf.Array):
                streams = list(contents)
            else:
                streams = [contents]
            for stream in streams:
                try:
                    raw = stream.read_bytes()
                    decoded = raw.decode("latin-1")
                    # Simple case: URL as a contiguous string
                    # Use bracket_dots=False - font may lack [ ] glyphs
                    defanged = re.sub(
                        r"(https?://)([^\s)<>]+)",
                        lambda m: defang_url(m.group(0), bracket_dots=False),
                        decoded,
                    )
                    # TJ arrays: URL split across kerned fragments
                    def defang_tj_array(tj_match):
                        tj_content = tj_match.group(1)
                        fragments = re.findall(r'\(([^)]*)\)', tj_content)
                        combined = ''.join(fragments)
                        if not re.search(r'https?://', combined):
                            return tj_match.group(0)
                        defanged_combined = re.sub(
                            r'(https?://)([^\s]+)',
                            lambda m2: defang_url(m2.group(0), bracket_dots=False),
                            combined,
                        )
                        if defanged_combined == combined:
                            return tj_match.group(0)
                        # Rebuild TJ array preserving per-fragment kerning
                        new_fragments = []
                        entries = re.findall(r'\(([^)]*)\)|([-\d.]+)', tj_content)
                        defang_pos = 0
                        for text, kern in entries:
                            if kern:
                                new_fragments.append(kern)
                            else:
                                frag_len = len(text)
                                new_text = defanged_combined[defang_pos:defang_pos + frag_len]
                                if defang_pos + frag_len >= len(defanged_combined):
                                    new_text = defanged_combined[defang_pos:]
                                escaped = new_text.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
                                new_fragments.append('(' + escaped + ')')
                                defang_pos += frag_len
                        if defang_pos < len(defanged_combined):
                            leftover = defanged_combined[defang_pos:]
                            escaped = leftover.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
                            new_fragments.append('(' + escaped + ')')
                        return '[' + ''.join(new_fragments) + '] TJ'

                    defanged = re.sub(
                        r'\[(.*?)\]\s*TJ',
                        defang_tj_array,
                        defanged,
                        flags=re.DOTALL,
                    )
                    # Change blue link color to black for defanged text
                    if defanged != decoded:
                        defanged = re.sub(r'0 0 1 rg', '0 0 0 rg', defanged)
                        defanged = re.sub(r'0 0 1 RG', '0 0 0 RG', defanged)
                    if defanged != decoded:
                        stream.write(defanged.encode("latin-1"))
                except Exception:
                    continue
        except Exception:
            continue


def defang_urls_in_pdf(pdf_path: str, password: str | None = None) -> int:
    """Neutralize all URI actions across the entire PDF and defang URLs in content streams."""
    count = 0
    with pikepdf.open(pdf_path, allow_overwriting_input=True, password=password or "") as pdf:
        # Iterate every page's /Annots array directly
        for page in pdf.pages:
            try:
                if "/Annots" not in page:
                    continue
                annots = page["/Annots"]
                if not isinstance(annots, pikepdf.Array):
                    continue
                annots_to_remove = []
                for i, annot_ref in enumerate(annots):
                    try:
                        annot = annot_ref
                        if isinstance(annot, pikepdf.Object) and not isinstance(annot, pikepdf.Dictionary):
                            continue
                        if not isinstance(annot, pikepdf.Dictionary):
                            continue
                        if _neutralize_annotation(annot):
                            annots_to_remove.append(i)
                            count += 1
                    except Exception:
                        continue
                for i in reversed(annots_to_remove):
                    del annots[i]
                if len(annots) == 0:
                    del page["/Annots"]
            except Exception:
                continue

        # Scan all objects for orphaned /S /URI actions
        for obj_num in pdf.objects:
            try:
                obj = pdf.get_object(obj_num)
                if not isinstance(obj, pikepdf.Dictionary):
                    continue
                if str(obj.get("/S", "")) == "/URI" and "/URI" in obj:
                    obj["/S"] = pikepdf.Name("/NoOp")
                    if "/URI" in obj:
                        del obj["/URI"]
                    count += 1
                elif "/A" in obj:
                    action = obj["/A"]
                    if isinstance(action, pikepdf.Dictionary) and str(action.get("/S", "")) == "/URI":
                        _neutralize_annotation(obj)
                        count += 1
            except Exception:
                continue

        _defang_content_streams(pdf)

        pdf.save(pdf_path)
    return count


def clean_pdf(input_path: str, output_path: str, password: str | None = None, level: str = "strict", defang_urls: bool = True) -> dict:
    """
    Copy the input PDF to output_path, then sanitize the copy in place.
    Returns a report of what was removed.
    """
    shutil.copy2(input_path, output_path)

    report: SanitizeReport = sanitize(
        output_path,
        return_report=True,
        level=level,
        password=password,
    )

    if report.error:
        os.remove(output_path)
        return {
            "input_file": os.path.basename(input_path),
            "output_file": None,
            "error": report.error,
            "elements_removed": 0,
            "details": [],
        }

    details = []

    if report.open_action_removed:
        details.append({"element": "OpenAction", "action": "removed"})

    if report.document_aa_removed:
        details.append({"element": "Document Additional Actions (/AA)", "action": "removed"})

    if report.javascript_in_names > 0:
        details.append({
            "element": f"Named JavaScript entries ({report.javascript_in_names})",
            "action": "removed",
        })

    if report.embedded_files > 0:
        details.append({
            "element": f"Embedded files ({report.embedded_files})",
            "action": "removed",
        })

    if report.xfa_form_removed:
        details.append({"element": "XFA form", "action": "removed"})

    if report.calculation_order_removed:
        details.append({"element": "AcroForm calculation order (/CO)", "action": "removed"})

    if report.pages_with_aa > 0:
        details.append({
            "element": f"Page-level Additional Actions ({report.pages_with_aa} page(s))",
            "action": "removed",
        })

    if report.annotations_with_actions > 0:
        types = ", ".join(report.annotation_action_types) if report.annotation_action_types else "unknown"
        details.append({
            "element": f"Annotation actions ({report.annotations_with_actions}): {types}",
            "action": "removed",
        })

    if report.annotations_with_js > 0:
        details.append({
            "element": f"Annotation JavaScript ({report.annotations_with_js})",
            "action": "removed",
        })

    if report.dangerous_uris_removed > 0:
        schemes = ", ".join(report.dangerous_uri_schemes_removed) if report.dangerous_uri_schemes_removed else "unknown"
        details.append({
            "element": f"Dangerous URIs ({report.dangerous_uris_removed}): {schemes}",
            "action": "removed",
        })

    if defang_urls:
        defanged_count = defang_urls_in_pdf(output_path, password=password)
        if defanged_count > 0:
            details.append({
                "element": f"URLs defanged ({defanged_count})",
                "action": "defanged",
            })

    output_size = os.path.getsize(output_path)

    return {
        "input_file": os.path.basename(input_path),
        "output_file": os.path.basename(output_path),
        "input_size": report.file_size_before,
        "output_size": output_size,
        "elements_removed": len(details),
        "details": details,
    }


def print_report(report: dict):
    print(f"\n{'='*60}")
    print(f"  PDF ANALYZER -- Clean Report")
    print(f"{'='*60}")

    if report.get("error"):
        print(f"  Error: {report['error']}")
        print(f"{'='*60}")
        return

    print(f"  Input:  {report['input_file']} ({report['input_size']} bytes)")
    print(f"  Output: {report['output_file']} ({report['output_size']} bytes)")
    print()

    if report["elements_removed"] == 0:
        print("  No malicious elements found -- file is already clean.")
    else:
        print(f"  {report['elements_removed']} element(s) cleaned:")
        for d in report["details"]:
            print(f"    * {d['element']} -- {d['action']}")

    print()
    print("  Recommendation: re-scan the cleaned file to verify score is 0.")
    print(f"{'='*60}")
