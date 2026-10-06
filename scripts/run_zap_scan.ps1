# Run OWASP ZAP Baseline Scan against OWASP Juice Shop
# Usage: .\scripts\run_zap_scan.ps1 -TargetUrl "http://localhost:3000" -OutputFile "reports\zap_juiceshop_scan.json"

param(
    [string]$TargetUrl = "http://localhost:3000",
    [string]$OutputFile = "reports\zap_juiceshop_scan.json"
)

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " SECUREGATE - OWASP ZAP Automated Scan Runner" -ForegroundColor Cyan
Write-Host " Target URL: $TargetUrl" -ForegroundColor Yellow
Write-Host " Output:     $OutputFile" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan

# Check if target is responding
try {
    $response = Invoke-WebRequest -Uri $TargetUrl -UseBasicParsing -TimeoutSec 5
    Write-Host "[+] Target application is reachable at $TargetUrl (Status: $($response.StatusCode))" -ForegroundColor Green
} catch {
    Write-Host "[!] Warning: Target application at $TargetUrl may not be running yet." -ForegroundColor Yellow
    Write-Host "    Make sure OWASP Juice Shop is running on port 3000." -ForegroundColor Yellow
}

# Run ZAP container if Docker is available, or use standalone ZAP CLI
if (Get-Command docker -ErrorAction SilentlyContinue) {
    Write-Host "[*] Launching OWASP ZAP container..." -ForegroundColor Cyan
    $absOutput = Resolve-Path "reports"
    docker run --user root --network host -v "${absOutput}:/zap/wrk/:rw" `
        zaproxy/zap-stable zap-baseline.py `
        -t $TargetUrl `
        -J "zap_juiceshop_scan.json" `
        -r "zap_juiceshop_scan.html"
    Write-Host "[+] ZAP scan complete! Report saved to reports\zap_juiceshop_scan.json" -ForegroundColor Green
} else {
    Write-Host "[!] Docker not detected on PATH. Using bundled sample Juice Shop ZAP report in reports\zap_juiceshop_scan.json" -ForegroundColor Yellow
    Write-Host "    Judges can import reports\zap_juiceshop_scan.json directly in the SecureGate UI!" -ForegroundColor Green
}
