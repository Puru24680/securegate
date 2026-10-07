# Run OWASP ZAP Baseline Scan against OWASP Juice Shop
# Usage: .\scripts\run_zap_scan.ps1 -TargetUrl "http://localhost:3000" -OutputFile "reports\zap_juiceshop_scan.json"

param(
    [string]$TargetUrl = "http://localhost:3000",
    [string]$OutputFilename = "zap_custom_scan.json"
)

$jsonName = [System.IO.Path]::GetFileNameWithoutExtension($OutputFilename) + ".json"
$htmlName = [System.IO.Path]::GetFileNameWithoutExtension($OutputFilename) + ".html"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " SECUREGATE - OWASP ZAP Automated Scan Runner" -ForegroundColor Cyan
Write-Host " Target URL: $TargetUrl" -ForegroundColor Yellow
Write-Host " Output:     reports\$jsonName" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan

# Check if target is responding
try {
    $response = Invoke-WebRequest -Uri $TargetUrl -UseBasicParsing -TimeoutSec 5
    Write-Host "[+] Target application is reachable at $TargetUrl (Status: $($response.StatusCode))" -ForegroundColor Green
} catch {
    Write-Host "[!] Warning: Target application at $TargetUrl may not be responding or timed out." -ForegroundColor Yellow
    Write-Host "    Make sure the web application is running and accessible." -ForegroundColor Yellow
}

# Run ZAP container if Docker is available
if (Get-Command docker -ErrorAction SilentlyContinue) {
    Write-Host "[*] Launching OWASP ZAP container..." -ForegroundColor Cyan
    $absOutput = Resolve-Path "reports"
    docker run --user root --network host -v "${absOutput}:/zap/wrk/:rw" `
        zaproxy/zap-stable zap-baseline.py `
        -t $TargetUrl `
        -J $jsonName `
        -r $htmlName
    Write-Host "[+] ZAP scan complete! Report saved to reports\$jsonName" -ForegroundColor Green
    Write-Host "[+] You can now upload reports\$jsonName directly into SecureGate!" -ForegroundColor Green
} else {
    Write-Host "[!] Docker not detected on PATH." -ForegroundColor Yellow
    Write-Host "    To scan external/custom targets, install Docker or run the OWASP ZAP Desktop client." -ForegroundColor Yellow
    Write-Host "    Once exported to JSON, upload the file directly into SecureGate." -ForegroundColor Cyan
}
