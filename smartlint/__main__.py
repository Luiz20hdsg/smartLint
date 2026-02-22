"""
SmartLint CLI — Command-line interface.

Usage:
    python -m smartlint analyze <path> [--format json|text] [--output file]
"""

import argparse
import json
import sys
import os

from .analyzer import Analyzer
from .models import Severity


# ANSI color codes
class Colors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


SEVERITY_COLORS = {
    Severity.CRITICAL: Colors.RED + Colors.BOLD,
    Severity.HIGH: Colors.RED,
    Severity.MEDIUM: Colors.YELLOW,
    Severity.LOW: Colors.CYAN,
    Severity.INFO: Colors.DIM,
}


def print_banner():
    print(f"""
{Colors.BOLD}{Colors.CYAN}╔═══════════════════════════════════════════════════════╗
║  SmartLint v0.1.0                                     ║
║  Static Analysis for Solidity · Inspired by Move      ║
╚═══════════════════════════════════════════════════════╝{Colors.RESET}
""")


def print_finding(finding, index):
    """Print a single finding in colored text format."""
    color = SEVERITY_COLORS.get(finding.severity, "")
    print(f"  {Colors.BOLD}[{index}] {color}{finding.severity.value}{Colors.RESET}"
          f" — {Colors.BOLD}{finding.title}{Colors.RESET}")
    print(f"      Checker:  {finding.checker.value}")
    print(f"      Contract: {finding.contract_name}")
    print(f"      Function: {finding.function_name}")
    print(f"      Location: {finding.location}")
    print(f"      {finding.message}")
    print(f"      {Colors.DIM}💡 Move: {finding.move_guarantee}{Colors.RESET}")
    print()


def print_summary(all_results):
    """Print a summary of all analysis results."""
    total_findings = sum(r.total_findings for r in all_results)
    total_contracts = sum(r.contracts_analyzed for r in all_results)
    total_functions = sum(r.functions_analyzed for r in all_results)
    files_analyzed = len([r for r in all_results if r.parse_error is None])
    parse_errors = len([r for r in all_results if r.parse_error is not None])

    # Count by severity
    severity_counts = {}
    checker_counts = {}
    for r in all_results:
        for f in r.findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
            checker_counts[f.checker.value] = checker_counts.get(f.checker.value, 0) + 1

    print(f"{Colors.BOLD}{'═' * 55}")
    print(f"  SUMMARY")
    print(f"{'═' * 55}{Colors.RESET}")
    print(f"  Files analyzed:     {files_analyzed}")
    if parse_errors:
        print(f"  Parse errors:       {Colors.RED}{parse_errors}{Colors.RESET}")
    print(f"  Contracts analyzed: {total_contracts}")
    print(f"  Functions analyzed: {total_functions}")
    print(f"  Total findings:     {Colors.BOLD}{total_findings}{Colors.RESET}")
    print()

    if severity_counts:
        print(f"  {Colors.BOLD}By Severity:{Colors.RESET}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                color = SEVERITY_COLORS.get(Severity(sev), "")
                print(f"    {color}{sev:12s}{Colors.RESET}  {count}")
        print()

    if checker_counts:
        print(f"  {Colors.BOLD}By Checker:{Colors.RESET}")
        for checker_name, count in sorted(checker_counts.items()):
            print(f"    {checker_name:20s}  {count}")
        print()


def cmd_analyze(args):
    """Run the analyze command."""
    analyzer = Analyzer()

    is_json = args.format == "json"

    if not is_json:
        print_banner()
        print(f"  Analyzing: {args.path}")
        print()

    results = analyzer.analyze(args.path)

    if is_json:
        output = {
            "results": [r.to_dict() for r in results],
            "summary": {
                "files_analyzed": len(results),
                "total_findings": sum(r.total_findings for r in results),
            }
        }
        json_str = json.dumps(output, indent=2, ensure_ascii=False)

        if args.output:
            with open(args.output, "w") as f:
                f.write(json_str)
            print(f"  Results written to: {args.output}")
        else:
            print(json_str)

    else:
        # Text format
        for result in results:
            rel_path = os.path.basename(result.file_path)
            if result.parse_error:
                print(f"  {Colors.RED}✗ {rel_path}: {result.parse_error}{Colors.RESET}")
                print()
                continue

            finding_count = result.total_findings
            if finding_count == 0:
                print(f"  {Colors.GREEN}✓ {rel_path}: No findings "
                      f"({result.contracts_analyzed} contracts, "
                      f"{result.functions_analyzed} functions){Colors.RESET}")
            else:
                color = Colors.RED if result.critical_count > 0 else Colors.YELLOW
                print(f"  {color}⚠ {rel_path}: {finding_count} finding(s) "
                      f"({result.contracts_analyzed} contracts, "
                      f"{result.functions_analyzed} functions){Colors.RESET}")

            for i, finding in enumerate(result.findings, 1):
                print_finding(finding, i)

        print_summary(results)

    # Exit with error code if findings found
    total = sum(r.total_findings for r in results)
    if total > 0:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="smartlint",
        description="SmartLint: Static Analysis for Solidity, Inspired by Move",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze Solidity files")
    analyze_parser.add_argument("path", help="Path to .sol file or directory")
    analyze_parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)"
    )
    analyze_parser.add_argument(
        "--output", "-o", help="Output file (for JSON format)"
    )

    args = parser.parse_args()

    if args.command == "analyze":
        cmd_analyze(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
