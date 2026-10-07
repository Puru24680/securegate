#!/usr/bin/env bash
# Run OWASP ZAP Baseline Scan against OWASP Juice Shop
# Usage: ./scripts/run_zap_scan.sh [TARGET_URL]

TARGET_URL="${1:-http://localhost:3000}"
OUTPUT_NAME="${2:-zap_custom_scan}"
OUTPUT_DIR="$(pwd)/reports"

echo "============================================================"
echo " SECUREGATE - OWASP ZAP Automated Scan Runner"
echo " Target URL: $TARGET_URL"
echo " Output Dir: $OUTPUT_DIR"
echo " Output Report: ${OUTPUT_NAME}.json"
echo "============================================================"

mkdir -p "$OUTPUT_DIR"

if command -v docker &> /dev/null; then
    echo "[*] Launching OWASP ZAP container against $TARGET_URL..."
    docker run --user root --network host -v "$OUTPUT_DIR:/zap/wrk/:rw" \
        zaproxy/zap-stable zap-baseline.py \
        -t "$TARGET_URL" \
        -J "${OUTPUT_NAME}.json" \
        -r "${OUTPUT_NAME}.html" || true
    echo "[+] ZAP scan complete! Report saved to reports/${OUTPUT_NAME}.json"
    echo "[+] You can now upload reports/${OUTPUT_NAME}.json directly into SecureGate!"
else
    echo "[!] Docker not found."
    echo "    To scan custom targets, install Docker or run the OWASP ZAP Desktop application."
    echo "    Export the report as JSON and upload it directly into SecureGate."
fi
