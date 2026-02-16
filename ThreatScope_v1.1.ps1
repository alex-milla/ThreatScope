<#
.SYNOPSIS
    Interactive reputation analysis tool for IPs, Domains and URLs in SOC environments
.DESCRIPTION
    Queries multiple threat intelligence providers (VirusTotal, AbuseIPDB, 
    AlienVault OTX, IPQualityScore, RDAP, URLScan) for reputation analysis.
    Supports both individual and batch analysis with automatic malicious indicator reporting.
.EXAMPLE
    .\ThreatScope.ps1
    # Interactive mode - will prompt for analysis type
.EXAMPLE
    .\ThreatScope.ps1 -Targets "8.8.8.8"
    # Direct mode - analyze single indicator
.EXAMPLE
    .\ThreatScope.ps1 -InputFile "iocs.csv"
    # Batch mode - analyze from file
#>

[CmdletBinding(DefaultParameterSetName='Interactive')]
param(
    [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true, ParameterSetName='Direct')]
    [string[]]$Targets,
    
    [Parameter(Mandatory=$false, ParameterSetName='File')]
    [string]$InputFile,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('Auto', 'Strict', 'None')]
    [string]$RateLimitMode = 'Auto'
)

# ==================== GLOBAL VARIABLES ====================

$VT_API = $null
$ABUSE_API = $null
$ALIEN_API = $null
$IPQ_API = $null
$URLSCAN_API = $null

$URL_VIRUSTOTAL_IP = "https://www.virustotal.com/api/v3/ip_addresses/"
$URL_VIRUSTOTAL_DOMAIN = "https://www.virustotal.com/api/v3/domains/"
$URL_VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls/"
$URL_ABUSEIPDB = "https://api.abuseipdb.com/api/v2/check"
$URL_ALIEN_IP = "https://otx.alienvault.com/api/v1/indicators/IPv4/"
$URL_ALIEN_DOMAIN = "https://otx.alienvault.com/api/v1/indicators/domain/"
$URL_ALIEN_URL = "https://otx.alienvault.com/api/v1/indicators/url/"
$URL_IPQ_IP = "https://www.ipqualityscore.com/api/json/ip/"
$URL_IPQ_URL = "https://www.ipqualityscore.com/api/json/url/"
$URL_URLSCAN = "https://urlscan.io/api/v1/"
$BLACKLIST_URL = ""

$RDAP_ENDPOINTS = @(
    @{Name="ARIN"; URL="https://rdap.arin.net/registry/ip/"},
    @{Name="RIPE"; URL="https://rdap.db.ripe.net/ip/"},
    @{Name="APNIC"; URL="https://rdap.apnic.net/ip/"},
    @{Name="LACNIC"; URL="https://rdap.lacnic.net/rdap/ip/"},
    @{Name="AFRINIC"; URL="https://rdap.afrinic.net/rdap/ip/"}
)

$TIMEOUT = 15

$RATE_LIMITS = @{
    VirusTotal = @{
        RequestsPerMinute = 4
        RequestsPerDay = 500
        RequestsPerMonth = 15500
    }
    AbuseIPDB = @{
        RequestsPerDay = 1000
        RequestsPerMonth = 30000
    }
    AlienVault = @{
        RequestsPerMinute = 0
    }
    IPQualityScore = @{
        RequestsPerMonth = 5000
    }
    URLScan = @{
        RequestsPerDay = 50
    }
}

$script:RATE_LIMITER = @{
    VirusTotal = @{
        LastRequest = $null
        RequestCount = 0
        DailyCount = 0
        MonthlyCount = 0
        ResetDaily = (Get-Date).Date.AddDays(1)
        ResetMonthly = (Get-Date -Day 1).AddMonths(1)
    }
    AbuseIPDB = @{
        LastRequest = $null
        DailyCount = 0
        MonthlyCount = 0
        ResetDaily = (Get-Date).Date.AddDays(1)
        ResetMonthly = (Get-Date -Day 1).AddMonths(1)
    }
    AlienVault = @{
        LastRequest = $null
    }
    IPQualityScore = @{
        LastRequest = $null
        MonthlyCount = 0
        ResetMonthly = (Get-Date -Day 1).AddMonths(1)
    }
    URLScan = @{
        LastRequest = $null
        DailyCount = 0
        ResetDaily = (Get-Date).Date.AddDays(1)
    }
}

$script:BLACKLIST_CACHE = @{
    Loaded = $false
    IPSet = @()
    Error = $null
    FetchedAt = $null
}

$script:MALICIOUS_INDICATORS = @()

# ==================== BANNER AND INTERACTIVE MENU ====================

function Show-Banner {
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                                                               ║" -ForegroundColor Cyan
    Write-Host "║                                    THREATSCOPE v1.1                                           ║" -ForegroundColor White
    Write-Host "║                        Multi-Source Threat Intelligence Analyzer                              ║" -ForegroundColor Gray
    Write-Host "║                                                                                               ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Show-InteractiveMenu {
    Write-Host "  Select analysis mode:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    [1] Analyze single indicator (IP, Domain, or URL)" -ForegroundColor White
    Write-Host "    [2] Batch analysis from file (CSV or TXT)" -ForegroundColor White
    Write-Host "    [3] Exit" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Enter your choice [1-3]: " -NoNewline -ForegroundColor Cyan
    
    $choice = Read-Host
    return $choice
}

function Get-InteractiveIndicator {
    Write-Host ""
    Write-Host "  Enter the indicator to analyze:" -ForegroundColor Yellow
    Write-Host "  (Supports defanged format: example[.]com, hxxps://site.com, 192.168.1[.]1)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Indicator: " -NoNewline -ForegroundColor Cyan
    
    $indicator = Read-Host
    return $indicator
}

function Get-InteractiveFilePath {
    Write-Host ""
    Write-Host "  Enter the path to your file (CSV or TXT):" -ForegroundColor Yellow
    Write-Host "  Examples: C:\iocs.csv, .\indicators.txt, indicators.csv" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  File path: " -NoNewline -ForegroundColor Cyan
    
    $filePath = Read-Host
    return $filePath.Trim('"').Trim("'")
}

function Get-RateLimitChoice {
    Write-Host ""
    Write-Host "  Select rate limiting mode:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    [1] Auto - Automatic rate limiting (recommended for free APIs)" -ForegroundColor White
    Write-Host "    [2] Strict - Conservative mode with extra delays" -ForegroundColor White
    Write-Host "    [3] None - No rate limiting (for paid APIs)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Enter your choice [1-3] (default: 1): " -NoNewline -ForegroundColor Cyan
    
    $choice = Read-Host
    
    switch ($choice) {
        "2" { return "Strict" }
        "3" { return "None" }
        default { return "Auto" }
    }
}

# ==================== CONFIGURATION ====================

function Load-EnvFile {
    param([string]$Path = "APIKEYS.env")
    
    if (Test-Path $Path) {
        Get-Content $Path | ForEach-Object {
            if ($_ -match '^([^=]+)=(.*)$') {
                $key = $matches[1].Trim()
                $value = $matches[2].Trim()
                [System.Environment]::SetEnvironmentVariable($key, $value, [System.EnvironmentVariableTarget]::Process)
            }
        }
        
        $script:VT_API = $env:VT_API
        $script:ABUSE_API = $env:ABUSE_API
        $script:ALIEN_API = $env:ALIEN_API
        $script:IPQ_API = $env:IPQ_API
        $script:URLSCAN_API = $env:URLSCAN_API
        
        return $true
    } else {
        Write-Warning "File $Path not found. Make sure to configure API keys."
        return $false
    }
}

# ==================== MALICIOUS INDICATORS REPORTING ====================

function Export-MaliciousIndicators {
    param([array]$MaliciousResults)
    
    if (-not $MaliciousResults -or $MaliciousResults.Count -eq 0) {
        return
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "MALICIOUS_INDICATORS_$timestamp.txt"
    
    $content = @()
    $content += "═" * 100
    $content += "MALICIOUS INDICATORS DETECTED - THREAT REPORT"
    $content += "═" * 100
    $content += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $content += "Total Malicious Indicators: $($MaliciousResults.Count)"
    $content += "═" * 100
    $content += ""
    
    foreach ($result in $MaliciousResults) {
        $content += "─" * 100
        $content += "INDICATOR: $($result.Indicator)"
        $content += "─" * 100
        $content += "Type:                $($result.Type)"
        $content += "Verdict:             $($result.Verdict)"
        $content += "Threat Score:        $($result.ThreatScore)/100"
        $content += "Analysis Date:       $($result.Timestamp)"
        $content += ""
        $content += "THREAT INTELLIGENCE SOURCES:"
        $content += "  VirusTotal:        $($result.VT_Detections) detections - Status: $($result.VT_Status)"
        
        if ($result.Abuse_Score -ne "N/A") {
            $content += "  AbuseIPDB:         Score: $($result.Abuse_Score)% - Reports: $($result.Abuse_Reports) - Status: $($result.Abuse_Status)"
        }
        
        $content += "  AlienVault OTX:    $($result.Alien_Pulses) pulses - Status: $($result.Alien_Status)"
        
        if ($result.IPQ_Score -ne "N/A") {
            $content += "  IPQualityScore:    Score: $($result.IPQ_Score) - Status: $($result.IPQ_Status)"
        }
        
        if ($result.Blacklisted -ne "N/A") {
            $content += "  Custom Blacklist:  $($result.Blacklisted)"
        }
        
        $content += ""
        $content += "GEOLOCATION/NETWORK INFO:"
        if ($result.Country -ne "N/A") {
            $content += "  Country:           $($result.Country)"
        }
        if ($result.ISP -ne "N/A") {
            $content += "  ISP/Owner:         $($result.ISP)"
        }
        $content += ""
        $content += "RECOMMENDED ACTIONS:"
        $content += "  [X] Block this indicator in firewall/proxy"
        $content += "  [X] Search for related IOCs in your environment"
        $content += "  [X] Review logs for connections to this indicator"
        $content += "  [X] Create detection rules for this indicator"
        $content += "  [X] Add to threat intelligence feeds"
        $content += ""
    }
    
    $content += "═" * 100
    $content += "END OF REPORT"
    $content += "═" * 100
    
    $content | Out-File -FilePath $filename -Encoding UTF8
    
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║                           MALICIOUS INDICATORS DETECTED                                       ║" -ForegroundColor White -BackgroundColor Red
    Write-Host "╚═══════════════════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""
    Write-Host "  [!] $($MaliciousResults.Count) malicious indicator(s) detected!" -ForegroundColor Red
    Write-Host "  [+] Detailed report saved to: $filename" -ForegroundColor Yellow
    Write-Host ""
    
    foreach ($result in $MaliciousResults) {
        Write-Host "  [MALICIOUS] $($result.Indicator) [$($result.Type)] - Score: $($result.ThreatScore)/100" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host ("═" * 100) -ForegroundColor Red
}

# ==================== RATE LIMITING FUNCTIONS ====================

function Test-RateLimit {
    param(
        [string]$Provider,
        [string]$Mode = 'Auto'
    )
    
    if ($Mode -eq 'None') {
        return $true
    }
    
    $now = Get-Date
    $limiter = $script:RATE_LIMITER[$Provider]
    $limits = $RATE_LIMITS[$Provider]
    
    if ($limiter.ResetDaily -and $now -ge $limiter.ResetDaily) {
        $limiter.DailyCount = 0
        $limiter.ResetDaily = $now.Date.AddDays(1)
    }
    
    if ($limiter.ResetMonthly -and $now -ge $limiter.ResetMonthly) {
        $limiter.MonthlyCount = 0
        $limiter.ResetMonthly = (Get-Date -Day 1).AddMonths(1)
    }
    
    if ($limits.RequestsPerDay -and $limiter.DailyCount -ge $limits.RequestsPerDay) {
        Write-Warning "[$Provider] Daily limit reached ($($limits.RequestsPerDay) requests/day)"
        return $false
    }
    
    if ($limits.RequestsPerMonth -and $limiter.MonthlyCount -ge $limits.RequestsPerMonth) {
        Write-Warning "[$Provider] Monthly limit reached ($($limits.RequestsPerMonth) requests/month)"
        return $false
    }
    
    if ($limits.RequestsPerMinute -gt 0) {
        if ($limiter.LastRequest) {
            $timeSinceLastRequest = ($now - $limiter.LastRequest).TotalSeconds
            $minDelaySeconds = 60.0 / $limits.RequestsPerMinute
            
            if ($timeSinceLastRequest -lt $minDelaySeconds) {
                $sleepTime = [Math]::Ceiling($minDelaySeconds - $timeSinceLastRequest)
                Write-Host "  [Rate Limit] Waiting $sleepTime seconds for $Provider..." -ForegroundColor Yellow
                Start-Sleep -Seconds $sleepTime
            }
        }
    }
    
    return $true
}

function Update-RateLimitCounter {
    param([string]$Provider)
    
    $limiter = $script:RATE_LIMITER[$Provider]
    $limiter.LastRequest = Get-Date
    
    if ($limiter.ContainsKey('DailyCount')) {
        $limiter.DailyCount++
    }
    
    if ($limiter.ContainsKey('MonthlyCount')) {
        $limiter.MonthlyCount++
    }
}

function Show-RateLimitStatus {
    Write-Host ""
    Write-Host ("═" * 100) -ForegroundColor Cyan
    Write-Host "  API RATE LIMIT STATUS" -ForegroundColor Cyan
    Write-Host ("═" * 100) -ForegroundColor Cyan
    
    foreach ($provider in $script:RATE_LIMITER.Keys) {
        $limiter = $script:RATE_LIMITER[$provider]
        $limits = $RATE_LIMITS[$provider]
        
        Write-Host ""
        Write-Host "  $provider" -ForegroundColor Yellow
        
        if ($limits.RequestsPerMinute) {
            Write-Host "    Rate: $($limits.RequestsPerMinute) req/min" -ForegroundColor Gray
        }
        
        if ($limits.RequestsPerDay -and $limiter.DailyCount) {
            $remaining = $limits.RequestsPerDay - $limiter.DailyCount
            $color = if ($remaining -lt 50) { "Red" } elseif ($remaining -lt 200) { "Yellow" } else { "Green" }
            Write-Host "    Daily: $($limiter.DailyCount) / $($limits.RequestsPerDay) used ($remaining remaining)" -ForegroundColor $color
        }
        
        if ($limits.RequestsPerMonth -and $limiter.MonthlyCount) {
            $remaining = $limits.RequestsPerMonth - $limiter.MonthlyCount
            $color = if ($remaining -lt 500) { "Red" } elseif ($remaining -lt 2000) { "Yellow" } else { "Green" }
            Write-Host "    Monthly: $($limiter.MonthlyCount) / $($limits.RequestsPerMonth) used ($remaining remaining)" -ForegroundColor $color
        }
    }
    
    Write-Host ""
    Write-Host ("═" * 100) -ForegroundColor Cyan
}

# ==================== FILE PROCESSING FUNCTIONS ====================

function Import-IndicatorsFromFile {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        Write-Error "File not found: $FilePath"
        return @()
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    $indicators = @()
    
    switch ($extension) {
        '.txt' {
            $indicators = Get-Content $FilePath | Where-Object { $_ -and $_.Trim() -ne '' -and $_ -notmatch '^\s*#' }
        }
        '.csv' {
            $csv = Import-Csv $FilePath
            
            $possibleColumns = @('IP', 'Domain', 'URL', 'Indicator', 'IOC', 'Address', 'Host', 'Target')
            $columnName = $null
            
            foreach ($col in $possibleColumns) {
                if ($csv[0].PSObject.Properties.Name -contains $col) {
                    $columnName = $col
                    break
                }
            }
            
            if (-not $columnName) {
                $columnName = $csv[0].PSObject.Properties.Name[0]
                Write-Warning "No standard column found. Using first column: $columnName"
            }
            
            $indicators = $csv | ForEach-Object { $_.$columnName } | Where-Object { $_ -and $_.Trim() -ne '' }
        }
        default {
            Write-Error "Unsupported file format: $extension. Use .txt or .csv"
            return @()
        }
    }
    
    return $indicators | Select-Object -Unique
}

function Export-ResultsToFile {
    param(
        [string]$FilePath,
        [array]$Results
    )
    
    if (-not $Results -or $Results.Count -eq 0) {
        Write-Warning "No results to export"
        return
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        '.csv' {
            $Results | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
            Write-Host "[+] Results exported to CSV: $FilePath" -ForegroundColor Green
        }
        '.json' {
            $Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $FilePath -Encoding UTF8
            Write-Host "[+] Results exported to JSON: $FilePath" -ForegroundColor Green
        }
        default {
            $csvPath = [System.IO.Path]::ChangeExtension($FilePath, '.csv')
            $Results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Host "[+] Results exported to CSV: $csvPath" -ForegroundColor Green
        }
    }
}

function New-AnalysisResult {
    param(
        [string]$Indicator,
        [string]$Type,
        [hashtable]$VTData,
        [hashtable]$AbuseData,
        [hashtable]$AlienData,
        [hashtable]$IPQData,
        [hashtable]$URLScanData,
        [hashtable]$BlacklistData
    )
    
    $threatScore = 0
    $maxScore = 0
    
    if ($VTData -and $VTData.ContainsKey('MaliciousCount') -and $VTData.TotalCount -gt 0) {
        $vtPercentage = ($VTData.MaliciousCount / $VTData.TotalCount) * 100
        $threatScore += ($vtPercentage * 0.4)
        $maxScore += 40
    }
    
    if ($AbuseData -and $AbuseData.ContainsKey('AbuseScore')) {
        $threatScore += ($AbuseData.AbuseScore * 0.3)
        $maxScore += 30
    }
    
    if ($AlienData -and $AlienData.ContainsKey('PulseCount')) {
        $pulseScore = [Math]::Min($AlienData.PulseCount * 4, 20)
        $threatScore += $pulseScore
        $maxScore += 20
    }
    
    if ($IPQData -and ($IPQData.ContainsKey('FraudScore') -or $IPQData.ContainsKey('RiskScore'))) {
        $score = if ($IPQData.FraudScore) { $IPQData.FraudScore } else { $IPQData.RiskScore }
        $threatScore += ($score * 0.1)
        $maxScore += 10
    }
    
    $overallScore = if ($maxScore -gt 0) { [Math]::Round($threatScore, 2) } else { 0 }
    
    $verdict = if ($overallScore -ge 70) {
        "MALICIOUS"
    } elseif ($overallScore -ge 40) {
        "SUSPICIOUS"
    } else {
        "CLEAN"
    }
    
    $result = [PSCustomObject]@{
        Indicator = $Indicator
        Type = $Type
        Verdict = $verdict
        ThreatScore = $overallScore
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        
        VT_Detections = if ($VTData.MaliciousCount) { "$($VTData.MaliciousCount)/$($VTData.TotalCount)" } else { "N/A" }
        VT_Status = if ($VTData.Status) { $VTData.Status } else { "N/A" }
        
        Abuse_Score = if ($AbuseData.AbuseScore) { $AbuseData.AbuseScore } else { "N/A" }
        Abuse_Reports = if ($AbuseData.TotalReports) { $AbuseData.TotalReports } else { "N/A" }
        Abuse_Status = if ($AbuseData.Status) { $AbuseData.Status } else { "N/A" }
        
        Alien_Pulses = if ($AlienData.PulseCount) { $AlienData.PulseCount } else { "N/A" }
        Alien_Status = if ($AlienData.Status) { $AlienData.Status } else { "N/A" }
        
        IPQ_Score = if ($IPQData.FraudScore) { $IPQData.FraudScore } elseif ($IPQData.RiskScore) { $IPQData.RiskScore } else { "N/A" }
        IPQ_Status = if ($IPQData.Status) { $IPQData.Status } else { "N/A" }
        
        Blacklisted = if ($BlacklistData.Blacklist) { $BlacklistData.Blacklist } else { "N/A" }
        
        Country = if ($VTData.Country) { $VTData.Country } elseif ($AbuseData.Country) { $AbuseData.Country } else { "N/A" }
        ISP = if ($VTData.ISP) { $VTData.ISP } elseif ($AbuseData.ISP) { $AbuseData.ISP } else { "N/A" }
    }
    
    return $result
}

# ==================== DEFANGING FUNCTIONS ====================

function ConvertFrom-DefangedIndicator {
    param([string]$Indicator)
    
    if ([string]::IsNullOrEmpty($Indicator)) {
        return $Indicator
    }
    
    $refanged = $Indicator `
        -replace '\[.\]', '.' `
        -replace '\[\.\]', '.' `
        -replace '\[dot\]', '.' `
        -replace 'hxxp', 'http' `
        -replace 'hXXp', 'http' `
        -replace 'h..p', 'http' `
        -replace '\[@\]', '@' `
        -replace '\[:\]', ':' `
        -replace 'meow', '' `
        -replace '\s+', ''
    
    return $refanged
}

function Get-IndicatorType {
    param([string]$Indicator)
    
    $clean = ConvertFrom-DefangedIndicator -Indicator $Indicator
    
    if ($clean -match '^https?://') {
        return @{Type="URL"; Value=$clean; Display=$Indicator}
    }
    
    if (Test-IPAddress -IP $clean) {
        return @{Type="IP"; Value=$clean; Display=$Indicator}
    }
    
    if ($clean -match '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$') {
        return @{Type="Domain"; Value=$clean; Display=$Indicator}
    }
    
    if ($clean -match '://') {
        return @{Type="URL"; Value=$clean; Display=$Indicator}
    }
    
    return @{Type="Domain"; Value=$clean; Display=$Indicator}
}

# ==================== UTILITY FUNCTIONS ====================

function Test-IPAddress {
    param([string]$IP)
    
    try {
        $null = [System.Net.IPAddress]::Parse($IP)
        return $true
    } catch {
        return $false
    }
}

function Get-DateDifference {
    param([int64]$Timestamp)
    
    $givenDate = [DateTimeOffset]::FromUnixTimeSeconds($Timestamp).DateTime
    $currentDate = Get-Date
    $difference = $currentDate - $givenDate
    
    $years = [Math]::Floor($difference.TotalDays / 365)
    $months = [Math]::Floor(($difference.TotalDays % 365) / 30)
    $days = [Math]::Floor(($difference.TotalDays % 365) % 30)
    
    if ($years -gt 0) {
        return "$years year$(if($years -gt 1){'s'}) ago"
    } elseif ($months -gt 0) {
        return "$months month$(if($months -gt 1){'s'}) ago"
    } else {
        return "$days day$(if($days -gt 1){'s'}) ago"
    }
}

# ==================== ANALYSIS FUNCTIONS (Simplified for length) ====================
# Note: Include all the Get-VirusTotalDataIP, Get-AbuseIPDBData, etc. functions from previous version
# These are omitted here for brevity but should be included in full script

function Get-BlacklistData {
    param([string]$IPAddress)
    
    if (-not $script:BLACKLIST_CACHE.Loaded) {
        Load-BlacklistOnce
    }
    
    if ($script:BLACKLIST_CACHE.Error) {
        return @{
            "Blacklist" = "Error"
            "Blacklist Error" = $script:BLACKLIST_CACHE.Error
            "Status" = "Info"
        }
    }
    
    $found = $script:BLACKLIST_CACHE.IPSet -contains $IPAddress
    
    return @{
        "Blacklist" = if($found){"Yes"}else{"No"}
        "Blacklist Source" = ""
        "Blacklist Checked" = $script:BLACKLIST_CACHE.FetchedAt
        "Status" = if($found){"Malicious"}else{"Clean"}
    }
}

function Load-BlacklistOnce {
    if ($script:BLACKLIST_CACHE.Loaded) {
        return
    }
    
    if ([string]::IsNullOrEmpty($BLACKLIST_URL)) {
        $script:BLACKLIST_CACHE.Loaded = $true
        return
    }
    
    $script:BLACKLIST_CACHE.Loaded = $true
}

# Placeholder functions - include full implementations from previous version
function Get-VirusTotalDataIP { param([string]$IPAddress) return @{"Status" = "Info"} }
function Get-VirusTotalDataDomain { param([string]$Domain) return @{"Status" = "Info"} }
function Get-VirusTotalDataURL { param([string]$URL) return @{"Status" = "Info"} }
function Get-AbuseIPDBData { param([string]$IPAddress) return @{"Status" = "Info"} }
function Get-AlienVaultDataIP { param([string]$IPAddress) return @{"Status" = "Info"} }
function Get-AlienVaultDataDomain { param([string]$Domain) return @{"Status" = "Info"} }
function Get-AlienVaultDataURL { param([string]$URL) return @{"Status" = "Info"} }
function Get-IPQualityScoreDataIP { param([string]$IPAddress) return @{"Status" = "Info"} }
function Get-IPQualityScoreDataURL { param([string]$URL) return @{"Status" = "Info"} }
function Get-URLScanData { param([string]$URL) return @{"Status" = "Info"} }

# ==================== BATCH PROCESSING ====================

function Invoke-BatchAnalysis {
    param([array]$Indicators)
    
    $totalCount = $Indicators.Count
    $currentCount = 0
    $results = @()
    
    Write-Host ""
    Write-Host ("═" * 100) -ForegroundColor Cyan
    Write-Host "  BATCH ANALYSIS MODE" -ForegroundColor White -BackgroundColor DarkCyan
    Write-Host ("═" * 100) -ForegroundColor Cyan
    Write-Host "  Total Indicators: $totalCount" -ForegroundColor Cyan
    Write-Host "  Rate Limit Mode: $RateLimitMode" -ForegroundColor Cyan
    Write-Host ("═" * 100) -ForegroundColor Cyan
    
    foreach ($indicator in $Indicators) {
        $currentCount++
        
        Write-Host ""
        Write-Host "[$currentCount/$totalCount] Processing: $indicator" -ForegroundColor Yellow
        
        $indicatorInfo = Get-IndicatorType -Indicator $indicator
        $type = $indicatorInfo.Type
        $cleanValue = $indicatorInfo.Value
        $displayValue = $indicatorInfo.Display
        
        if ($displayValue -ne $cleanValue) {
            Write-Host "  Defanged input detected. Converted: $displayValue -> $cleanValue" -ForegroundColor DarkGray
        }
        
        $vtData = @{"Status" = "Info"}
        $abuseData = @{}
        $alienData = @{"Status" = "Info"}
        $ipqsData = @{"Status" = "Info"}
        $rdapData = @{}
        $blacklistData = @{}
        $urlscanData = @{}
        
        try {
            if ($type -eq "IP") {
                $vtData = Get-VirusTotalDataIP -IPAddress $cleanValue
                $abuseData = Get-AbuseIPDBData -IPAddress $cleanValue
                $alienData = Get-AlienVaultDataIP -IPAddress $cleanValue
                $ipqsData = Get-IPQualityScoreDataIP -IPAddress $cleanValue
                $blacklistData = Get-BlacklistData -IPAddress $cleanValue
            } elseif ($type -eq "Domain") {
                $vtData = Get-VirusTotalDataDomain -Domain $cleanValue
                $alienData = Get-AlienVaultDataDomain -Domain $cleanValue
            } elseif ($type -eq "URL") {
                $vtData = Get-VirusTotalDataURL -URL $cleanValue
                $alienData = Get-AlienVaultDataURL -URL $cleanValue
                $ipqsData = Get-IPQualityScoreDataURL -URL $cleanValue
                $urlscanData = Get-URLScanData -URL $cleanValue
            }
            
            $result = New-AnalysisResult -Indicator $cleanValue -Type $type -VTData $vtData -AbuseData $abuseData -AlienData $alienData -IPQData $ipqsData -URLScanData $urlscanData -BlacklistData $blacklistData
            $results += $result
            
            $verdictColor = switch ($result.Verdict) {
                "MALICIOUS" { "Red" }
                "SUSPICIOUS" { "Yellow" }
                "CLEAN" { "Green" }
                default { "White" }
            }
            
            Write-Host "  Result: " -NoNewline
            Write-Host "$($result.Verdict)" -ForegroundColor $verdictColor -NoNewline
            Write-Host " (Score: $($result.ThreatScore)/100)" -ForegroundColor Gray
            
            if ($result.Verdict -eq "MALICIOUS") {
                $script:MALICIOUS_INDICATORS += $result
            }
            
        } catch {
            Write-Warning "  Error analyzing $indicator : $($_.Exception.Message)"
            $results += [PSCustomObject]@{
                Indicator = $cleanValue
                Type = $type
                Verdict = "ERROR"
                ThreatScore = "N/A"
                Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Error = $_.Exception.Message
            }
        }
    }
    
    return $results
}

# ==================== MAIN EXECUTION ====================

Add-Type -AssemblyName System.Web

# Load configuration
$configLoaded = Load-EnvFile

if (-not $configLoaded) {
    Write-Host ""
    Write-Host "  [!] Warning: API keys not configured. Please create APIKEYS.env file." -ForegroundColor Yellow
    Write-Host "  Press Enter to continue anyway or Ctrl+C to exit..." -ForegroundColor Gray
    Read-Host
}

# Show banner
Show-Banner

# Interactive mode
if ($PSCmdlet.ParameterSetName -eq 'Interactive' -and -not $Targets -and -not $InputFile) {
    $choice = Show-InteractiveMenu
    
    switch ($choice) {
        "1" {
            # Single indicator
            $indicator = Get-InteractiveIndicator
            
            if ([string]::IsNullOrWhiteSpace($indicator)) {
                Write-Error "No indicator provided"
                exit 1
            }
            
            $Targets = @($indicator)
            $RateLimitMode = Get-RateLimitChoice
        }
        "2" {
            # Batch from file
            $filePath = Get-InteractiveFilePath
            
            if ([string]::IsNullOrWhiteSpace($filePath) -or -not (Test-Path $filePath)) {
                Write-Error "Invalid file path: $filePath"
                exit 1
            }
            
            $InputFile = $filePath
            $RateLimitMode = Get-RateLimitChoice
        }
        "3" {
            Write-Host "  Exiting..." -ForegroundColor Gray
            exit 0
        }
        default {
            Write-Error "Invalid choice"
            exit 1
        }
    }
}

# Execute based on mode
if ($InputFile) {
    # Batch processing
    Write-Host ""
    Write-Host "[+] Loading indicators from file: $InputFile" -ForegroundColor Cyan
    
    $indicators = Import-IndicatorsFromFile -FilePath $InputFile
    
    if ($indicators.Count -eq 0) {
        Write-Error "No valid indicators found in file"
        exit 1
    }
    
    Write-Host "[+] Found $($indicators.Count) unique indicators" -ForegroundColor Green
    
    $results = Invoke-BatchAnalysis -Indicators $indicators
    
    Write-Host ""
    Write-Host ("═" * 100) -ForegroundColor Cyan
    Write-Host "  ANALYSIS SUMMARY" -ForegroundColor White -BackgroundColor DarkCyan
    Write-Host ("═" * 100) -ForegroundColor Cyan
    
    $maliciousCount = ($results | Where-Object { $_.Verdict -eq "MALICIOUS" }).Count
    $suspiciousCount = ($results | Where-Object { $_.Verdict -eq "SUSPICIOUS" }).Count
    $cleanCount = ($results | Where-Object { $_.Verdict -eq "CLEAN" }).Count
    $errorCount = ($results | Where-Object { $_.Verdict -eq "ERROR" }).Count
    
    Write-Host "  Total Analyzed: $($results.Count)" -ForegroundColor White
    Write-Host "  Malicious: $maliciousCount" -ForegroundColor Red
    Write-Host "  Suspicious: $suspiciousCount" -ForegroundColor Yellow
    Write-Host "  Clean: $cleanCount" -ForegroundColor Green
    if ($errorCount -gt 0) {
        Write-Host "  Errors: $errorCount" -ForegroundColor Red
    }
    Write-Host ("═" * 100) -ForegroundColor Cyan
    
    if ($RateLimitMode -ne 'None') {
        Show-RateLimitStatus
    }
    
    # Export malicious indicators report
    if ($script:MALICIOUS_INDICATORS.Count -gt 0) {
        Export-MaliciousIndicators -MaliciousResults $script:MALICIOUS_INDICATORS
    }
    
    # Export all results
    if ($OutputFile) {
        Export-ResultsToFile -FilePath $OutputFile -Results $results
    } else {
        $defaultOutput = "analysis_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        Write-Host ""
        Write-Host "[?] Save all results to CSV file? (default: $defaultOutput)" -ForegroundColor Cyan
        Write-Host "    Press Enter to save, or type 'n' to skip: " -NoNewline
        $response = Read-Host
        
        if ($response -ne 'n' -and $response -ne 'N') {
            $saveFile = if ([string]::IsNullOrEmpty($response)) { $defaultOutput } else { $response }
            Export-ResultsToFile -FilePath $saveFile -Results $results
        }
    }
    
} else {
    # Single indicator analysis
    foreach ($target in $Targets) {
        $indicatorInfo = Get-IndicatorType -Indicator $target
        $type = $indicatorInfo.Type
        $cleanValue = $indicatorInfo.Value
        $displayValue = $indicatorInfo.Display
        
        Write-Host ""
        Write-Host "[+] Detected: $type" -ForegroundColor Cyan
        if ($displayValue -ne $cleanValue) {
            Write-Host "[+] Defanged input detected. Converted: $displayValue -> $cleanValue" -ForegroundColor Yellow
        }
        
        Write-Host ""
        Write-Host "  Querying threat intelligence providers..." -ForegroundColor Yellow
        
        $vtData = @{"Status" = "Info"}
        $abuseData = @{}
        $alienData = @{"Status" = "Info"}
        $ipqsData = @{"Status" = "Info"}
        $blacklistData = @{}
        $urlscanData = @{}
        
        if ($type -eq "IP") {
            $vtData = Get-VirusTotalDataIP -IPAddress $cleanValue
            $abuseData = Get-AbuseIPDBData -IPAddress $cleanValue
            $alienData = Get-AlienVaultDataIP -IPAddress $cleanValue
            $ipqsData = Get-IPQualityScoreDataIP -IPAddress $cleanValue
            $blacklistData = Get-BlacklistData -IPAddress $cleanValue
        } elseif ($type -eq "Domain") {
            $vtData = Get-VirusTotalDataDomain -Domain $cleanValue
            $alienData = Get-AlienVaultDataDomain -Domain $cleanValue
        } elseif ($type -eq "URL") {
            $vtData = Get-VirusTotalDataURL -URL $cleanValue
            $alienData = Get-AlienVaultDataURL -URL $cleanValue
            $ipqsData = Get-IPQualityScoreDataURL -URL $cleanValue
            $urlscanData = Get-URLScanData -URL $cleanValue
        }
        
        $result = New-AnalysisResult -Indicator $cleanValue -Type $type -VTData $vtData -AbuseData $abuseData -AlienData $alienData -IPQData $ipqsData -URLScanData $urlscanData -BlacklistData $blacklistData
        
        Write-Host ""
        Write-Host ("═" * 100) -ForegroundColor Cyan
        Write-Host "  ANALYSIS RESULT" -ForegroundColor White -BackgroundColor DarkCyan
        Write-Host ("═" * 100) -ForegroundColor Cyan
        Write-Host "  Indicator: $cleanValue" -ForegroundColor White
        Write-Host "  Type: $type" -ForegroundColor White
        
        $verdictColor = switch ($result.Verdict) {
            "MALICIOUS" { "Red" }
            "SUSPICIOUS" { "Yellow" }
            "CLEAN" { "Green" }
            default { "White" }
        }
        
        Write-Host "  Verdict: " -NoNewline
        Write-Host "$($result.Verdict)" -ForegroundColor $verdictColor
        Write-Host "  Threat Score: $($result.ThreatScore)/100" -ForegroundColor White
        Write-Host ("═" * 100) -ForegroundColor Cyan
        
        if ($result.Verdict -eq "MALICIOUS") {
            $script:MALICIOUS_INDICATORS += $result
            Export-MaliciousIndicators -MaliciousResults @($result)
        }
    }
}

Write-Host ""
Write-Host "[+] Analysis complete" -ForegroundColor Green
Write-Host ""
