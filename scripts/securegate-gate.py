#!/usr/bin/env python3
"""
SecureGate DevSecOps CLI & CI/CD Runner
Ingests OWASP ZAP scan reports, evaluates pre-release security gates,
and enforces CI/CD build pass/fail policies with rich terminal summaries
and GitHub Actions Step Summary integration.
"""
import argparse
import json
import os
import sys
import urllib.request
import urllib.error


def format_status(status: str) -> str:
    color_map = {
        "PASS": "\033[92m✔ PASS\033[0m",
        "REVIEW": "\033[93m⚠ REVIEW\033[0m",
        "BLOCK": "\033[91m✖ BLOCK\033[0m",
    }
    return color_map.get(status, status)


def write_github_summary(scan: dict, release_status: str, target_url: str):
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    icon = "🔴" if release_status == "BLOCK" else ("🟡" if release_status == "REVIEW" else "🟢")
    md = [
        f"## {icon} SecureGate Pre-Release Security Evaluation: {release_status}",
        "",
        f"- **Target Application:** `{target_url}`",
        f"- **Release Gate Status:** **{release_status}**",
        f"- **Security Score:** **{scan.get('security_score', 'N/A')}/100**",
        f"- **Total Findings:** **{scan.get('total_findings', 0)}**",
        "",
        "### 🛡️ Vulnerability Severity Breakdown",
        "",
        "| Severity | Count | Gate Policy |",
        "|---|:---:|:---:|",
        f"| 🚨 **Critical** | {scan.get('critical_count', 0)} | BLOCK |",
        f"| 🔴 **High** | {scan.get('high_count', 0)} | BLOCK |",
        f"| 🟡 **Medium** | {scan.get('medium_count', 0)} | REVIEW |",
        f"| 🔵 **Low** | {scan.get('low_count', 0)} | PASS |",
        f"| ⚪ **Info** | {scan.get('info_count', 0)} | PASS |",
        "",
    ]

    findings = scan.get("findings", [])
    if findings:
        md.extend([
            "### 🔍 Detected Security Findings",
            "",
            "| Finding | Severity | CWE | Method | Parameter | URL |",
            "|---|---|---|---|---|---|",
        ])
        for f in findings[:20]:
            name = f.get('name', 'N/A')
            sev = f.get('severity', 'N/A')
            cwe = f.get('cwe_id', 'N/A')
            method = f.get('method', 'GET')
            param = f.get('parameter', '-') or '-'
            url = f.get('url', '-')
            md.append(f"| {name} | **{sev}** | {cwe} | `{method}` | `{param}` | `{url}` |")

        if len(findings) > 20:
            md.append(f"\n*...and {len(findings) - 20} additional findings.*")

    md.extend([
        "",
        "---",
        "*Powered by SecureGate DevSecOps Quality Gate*",
    ])

    try:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write("\n".join(md) + "\n")
    except Exception as e:
        print(f"[SecureGate] Warning: Could not write GitHub step summary: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="SecureGate CI/CD Pre-Release Quality Gate Evaluator"
    )
    parser.add_argument(
        "--report",
        required=True,
        help="Path to OWASP ZAP JSON scan report"
    )
    parser.add_argument(
        "--api-url",
        default=os.environ.get("SECUREGATE_API_URL", "https://securegate-ebon.vercel.app"),
        help="SecureGate API Base URL (default: https://securegate-ebon.vercel.app)"
    )
    parser.add_argument(
        "--project-id",
        type=int,
        default=int(os.environ.get("SECUREGATE_PROJECT_ID", "1")),
        help="Target Project ID in SecureGate (default: 1)"
    )
    parser.add_argument(
        "--target-url",
        default="",
        help="Target URL scanned (optional override)"
    )
    parser.add_argument(
        "--github-summary",
        action="store_true",
        help="Write rich markdown summary to $GITHUB_STEP_SUMMARY"
    )
    parser.add_argument(
        "--fail-on",
        choices=["BLOCK", "REVIEW"],
        default="BLOCK",
        help="Gate failure threshold: fail on BLOCK (default) or fail on REVIEW/BLOCK"
    )

    args = parser.parse_args()

    # Load report file
    if not os.path.exists(args.report):
        print(f"\033[91m[ERROR]\033[0m Report file not found: {args.report}", file=sys.stderr)
        sys.exit(2)

    try:
        with open(args.report, "r", encoding="utf-8", errors="replace") as f:
            report_data = json.load(f)
    except Exception as e:
        print(f"\033[91m[ERROR]\033[0m Failed to parse report JSON: {e}", file=sys.stderr)
        sys.exit(2)

    api_base = args.api_url.rstrip("/")
    upload_url = f"{api_base}/api/scans/upload"

    print("=" * 65)
    print(" 🛡️  SecureGate DevSecOps Pre-Release Quality Gate")
    print("=" * 65)
    print(f" Target API:    {api_base}")
    print(f" Report File:   {args.report}")
    print(f" Project ID:    {args.project_id}")
    print(" Uploading scan report and evaluating release gates...")

    payload = {
        "project_id": args.project_id,
        "report": report_data,
        "target_url": args.target_url or None,
    }

    req = urllib.request.Request(
        upload_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "SecureGate-CLI/1.0"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=30.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="replace")
        print(f"\033[91m[ERROR]\033[0m API request failed ({e.code}): {err_msg}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"\033[91m[ERROR]\033[0m Failed to connect to SecureGate API: {e}", file=sys.stderr)
        sys.exit(2)

    scan = data.get("scan", {})
    release_status = scan.get("release_status", "BLOCK")
    score = scan.get("security_score", 0)
    total_findings = scan.get("total_findings", 0)
    target = scan.get("target_url", args.target_url or "Target Web App")

    print("\n" + "-" * 65)
    print(f" TARGET:         {target}")
    print(f" SECURITY SCORE: {score}/100")
    print(f" TOTAL FINDINGS: {total_findings}")
    print(f" RELEASE GATE:   {format_status(release_status)}")
    print("-" * 65)
    print(" SEVERITY SUMMARY:")
    print(f"  🚨 Critical:      {scan.get('critical_count', 0)}")
    print(f"  🔴 High:          {scan.get('high_count', 0)}")
    print(f"  🟡 Medium:        {scan.get('medium_count', 0)}")
    print(f"  🔵 Low:           {scan.get('low_count', 0)}")
    print(f"  ⚪ Informational: {scan.get('info_count', 0)}")
    print("-" * 65)

    if args.github_summary or os.environ.get("GITHUB_STEP_SUMMARY"):
        write_github_summary(scan, release_status, target)

    # Fail pipeline if status meets or exceeds failure threshold
    should_fail = False
    if args.fail_on == "BLOCK" and release_status == "BLOCK":
        should_fail = True
    elif args.fail_on == "REVIEW" and release_status in ("BLOCK", "REVIEW"):
        should_fail = True

    if should_fail:
        print(f"\n\033[91m✖ RELEASE GATE FAILED: {release_status}\033[0m")
        print(" Critical or High severity vulnerabilities violate the pre-release security policy.")
        print(" Pipeline execution halted. Remediate vulnerabilities before deploying.\n")
        sys.exit(1)
    else:
        print(f"\n\033[92m✔ RELEASE GATE PASSED: {release_status}\033[0m")
        print(" Application meets security quality gates for deployment.\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
