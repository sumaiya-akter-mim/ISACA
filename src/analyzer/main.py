import argparse
import os
import glob

from .dast import scan_sql_injection
from .sast import analyze_python_file
from .dump_audit import identify_hashes_from_dump
from .correlate import correlate
from .report import to_json, to_markdown, to_html


def main():
    parser = argparse.ArgumentParser(description="SecChain Analyzer CLI")
    parser.add_argument("--target", required=True, help="Target base URL (e.g., http://localhost:5000)")
    parser.add_argument("--source_dir", required=True, help="Directory containing Python source code")
    parser.add_argument("--dump", required=True, help="Path to database dump file")
    parser.add_argument("--out_dir", default="reports", help="Output directory for reports")
    parser.add_argument("--html", action="store_true", help="Also generate HTML report")
    args = parser.parse_args()

    # Build candidate URLs: root with common params and seeded endpoints
    urls = [
        f"{args.target}/search?q=test",
        f"{args.target}/login?user=alice&pass=pass",
        f"{args.target}/item?id=1",
    ]

    dast_findings = scan_sql_injection(urls)

    # SAST across Python files
    py_files = glob.glob(os.path.join(args.source_dir, "**", "*.py"), recursive=True)
    sast_findings = []
    for f in py_files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                src = fh.read()
            sast_findings.extend(analyze_python_file(f, src))
        except Exception:
            continue

    # Dump audit
    try:
        with open(args.dump, "r", encoding="utf-8") as fh:
            dump_text = fh.read()
        dump_findings = identify_hashes_from_dump(dump_text)
    except Exception:
        dump_findings = []

    # Correlate
    risk = correlate(dast_findings, sast_findings, dump_findings)

    # Write reports
    os.makedirs(args.out_dir, exist_ok=True)
    json_path = os.path.join(args.out_dir, "report.json")
    md_path = os.path.join(args.out_dir, "report.md")
    with open(json_path, "w", encoding="utf-8") as fh:
        fh.write(to_json(risk))
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(to_markdown(risk))
    if args.html:
        html_path = os.path.join(args.out_dir, "report.html")
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(to_html(risk))

    print(f"Reports written to {args.out_dir}")


if __name__ == "__main__":
    main()