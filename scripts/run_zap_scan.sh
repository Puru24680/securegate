#!/usr/bin/env bash
# Run OWASP ZAP Baseline Scan against OWASP Juice Shop
# Usage: ./scripts/run_zap_scan.sh [TARGET_URL]

TARGET_URL="${1:-http://localhost:3000}"
OUTPUT_DIR="$(pwd)/reports"

echo "============================================================"
echo " SECUREGATE - OWASP ZAP Automated Scan Runner"
echo " Target URL: $TARGET_URL"
echo " Output Dir: $OUTPUT_DIR"
echo "============================================================"

mkdir -p "$OUTPUT_DIR"

if command -v docker &> /dev/null; then
    echo "[*] Launching OWASP ZAP container..."
    docker run --user root --network host -v "$OUTPUT_DIR:/zap/wrk/:rw" \
        zaproxy/zap-stable zap-baseline.py \
        -t "$TARGET_URL" \
        -J "zap_juiceshop_scan.json" \
        -r "zap_juiceshop_scan.html" || true
    echo "[+] ZAP scan complete! Report saved to reports/zap_juiceshop_scan.json"
else
    echo "[!] Docker not found. Use pre-generated reports/zap_juiceshop_scan.json for demo."
fi
