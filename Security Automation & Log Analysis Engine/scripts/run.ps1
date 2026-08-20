# File handling( assinging files for variables)
$authLog    = "./ProjectDataset/auth.log"
$accessLog  = "./ProjectDataset/access.log"
$psLog      = "./ProjectDataset/powershell_log.txt"
$iocFile    = "./ProjectDataset/ioc.txt"
$report     = "investigation_report.txt"

$alertCount = 0  #Variable for all detections
$badPaths   = @("/admin", "wp-login", ".php", "/etc/passwd")


# Threat Intelligence & Automation Functions
function Get-IPReputation {
    param ([string]$IPAddress)
    
    $apiKey = "a24e64b7ad9c9cbdd3cebbc0d1dadfe3b800bd1d4105427cda571d05815d5ab1089ed91f6e9ff845"
    $headers = @{ "Key" = $apiKey; "Accept" = "application/json" }
    
    try {
        $uri = "https://api.abuseipdb.com/api/v2/check?ipAddress=$IPAddress"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        return $response.data.abuseConfidenceScore
    } catch {
        return 0 # Fallback if offline or API limit hit
    }
}

function Send-SOCWebhookAlert {
    param (
        [string]$IPAddress,
        [int]$ThreatScore,
        [string]$LogSource,
        [string]$ThreatDetail
    )
    
    $webhookUrl = "https://discord.com/api/webhooks/1535088155852546078/ELaqTkhxYHunneEwcU-T0svvFFnojOe4fci13V0UoucHt_PLRH4IoqnuDnOTLgex-hXM"
    
    # Construct a clean JSON payload string directly to avoid ConvertTo-Json encoding bugs
    $message = "🚨 **HIGH RISK THREAT DETECTED**`n• **Target IP:** $IPAddress`n• **AbuseIPDB Score:** $ThreatScore%`n• **Log Source:** $LogSource`n• **Details:** $ThreatDetail"
    
    $payloadObj = @{
        username = "Mr Hacker Bot"
        content  = $message
    }
    
    $jsonBody = $payloadObj | ConvertTo-Json -Compress
    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($jsonBody)

    try {
        Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $utf8Bytes -ContentType 'application/json; charset=utf-8'
        Write-Host "[+] Webhook Alert sent successfully for $IPAddress" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to send Webhook Alert: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Message of Investigation preparation
Write-Host "== Beginning SOC Investigation ==" -ForegroundColor Cyan
"SOC INVESTIGATION REPORT" | Out-File $report
"Generated on: $(Get-Date)" | Add-Content $report
$failed = Select-String -Path $authLog -Pattern "Failed password"
if ($failed) {
    $alertCount++
    "ALERT: Found $($failed.Count) failed login attempts." | Add-Content $report
    $failed | ForEach-Object { "Log Entry: $($_.Line)" } | Add-Content $report
    
    "--------------------------" | Add-Content $report
}

# Detection 2: Web Paths
foreach ($path in $badPaths) {
    if (Select-String -Path $accessLog -Pattern $path) {
        $alertCount++
        Write-Host "[!] Found suspicious path: $path" -ForegroundColor Red
        "ALERT: Malicious path detected: $path" | Add-Content $report
    }
}

# Detection 3: IOC
$iocs = Get-Content $iocFile
foreach ($ip in $iocs) {
    if ($ip.Trim() -and (Select-String -Path $authLog -Pattern $ip)) {
        $alertCount++
        "WARNING: Malicious IP [$ip] detected!" | Add-Content $report
    }
}


# Read extracted IOC IPs directly and run dynamic enrichment
$rawIOCs = Get-Content $iocFile | Where-Object { $_.Trim() -ne "" -and -not $_.StartsWith("#") }

foreach ($entry in $rawIOCs) {
    $cleanIP = $entry.Trim()

    # Regex: Only process valid IPv4 addresses
    if ($cleanIP -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        continue
    }

    Write-Host "[*] Querying Threat Intel for $cleanIP..." -ForegroundColor Cyan
    $reputationScore = Get-IPReputation -IPAddress $cleanIP

    if ($reputationScore -ge 0) {
        Write-Host "[!] Triggering Webhook Alert for $cleanIP..." -ForegroundColor Red
        Send-SOCWebhookAlert -IPAddress $cleanIP `
                             -ThreatScore $reputationScore `
                             -LogSource "auth.log / access.log" `
                             -ThreatDetail "IOC Match Detected"
    }
}

Write-Host "[*] Checking PowerShell Activity..."
$suspiciousPS = Select-String -Path $psLog -Pattern "EncodedCommand", "Bypass", "Invoke-WebRequest"
if ($suspiciousPS) {
    $alertCount++
    "ALERT: Suspicious PowerShell execution pattern found!" | Add-Content $report
    $suspiciousPS | ForEach-Object { "Detail: $($_.Line)" } | Add-Content $report
}



#SUMMARY Code

# Gather the specific IPs found.
$foundIPs = @()
$iocs = Get-Content $iocFile
foreach ($ip in $iocs) {
    if ($ip.Trim() -and (Select-String -Path $authLog, $accessLog -Pattern $ip -Quiet)) {
        $foundIPs += $ip.Trim()
    }
}

# Decides with Risk Level.
if ($alertCount -ge 3) { $risk = "High Risk" }
elseif ($alertCount -ge 1) { $risk = "Medium Risk" }
else { $risk = "Low Risk" }

# Writes summary in detail.
"--------------------------" | Add-Content $report
"Total Alerts Detected: $alertCount" | Add-Content $report
"Final Risk Level: $risk" | Add-Content $report
"Malicious IPs Found: $(if($foundIPs){$foundIPs -join ', '} else {'None'})" | Add-Content $report

# Visual terminal output of summary.
Write-Host "`n== Investigation Summary ==" -ForegroundColor Cyan
Write-Host "Total Alerts: $alertCount"
Write-Host "Risk Level: $risk" -ForegroundColor Yellow
if ($foundIPs) {
    Write-Host "Malicious IPs: $($foundIPs -join ', ')" -ForegroundColor Red
}
Write-Host "Investigation finished. Report saved to: $report" -ForegroundColor Green



Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "   COMPH2705 SOC THREAT HUNTING PIPELINE  " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Execute Core Detection Engine

Write-Host "`n[*] Pipeline Execution Completed." -ForegroundColor Green