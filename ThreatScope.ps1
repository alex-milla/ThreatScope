<#
.SYNOPSIS
    Reputation analysis tool for IPs, Domains and URLs in SOC environments
.DESCRIPTION
    Queries multiple threat intelligence providers (VirusTotal, AbuseIPDB, 
    AlienVault OTX, IPQualityScore, RDAP, URLScan) for reputation analysis
.PARAMETER Targets
    One or more IP addresses, domains or URLs to analyze (supports defanged format)
.EXAMPLE
    .\Analyze-Reputation.ps1 -Targets "8.8.8.8"
.EXAMPLE
    .\Analyze-Reputation.ps1 -Targets "example[.]com", "hxxps://malware[.]com/payload"
.EXAMPLE
    .\Analyze-Reputation.ps1 -Targets "192.168.1[.]1", "google.com", "https://example.com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [string[]]$Targets
)

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
    } else {
        Write-Warning "File $Path not found. Make sure to configure API keys."
    }
}

Load-EnvFile

# API Keys
$VT_API = $env:VT_API
$ABUSE_API = $env:ABUSE_API
$ALIEN_API = $env:ALIEN_API
$IPQ_API = $env:IPQ_API
$URLSCAN_API = $env:URLSCAN_API

# API URLs
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

# RDAP Endpoints
$RDAP_ENDPOINTS = @(
    @{Name="ARIN"; URL="https://rdap.arin.net/registry/ip/"},
    @{Name="RIPE"; URL="https://rdap.db.ripe.net/ip/"},
    @{Name="APNIC"; URL="https://rdap.apnic.net/ip/"},
    @{Name="LACNIC"; URL="https://rdap.lacnic.net/rdap/ip/"},
    @{Name="AFRINIC"; URL="https://rdap.afrinic.net/rdap/ip/"}
)

$TIMEOUT = 15

$script:BLACKLIST_CACHE = @{
    Loaded = $false
    IPSet = @()
    Error = $null
    FetchedAt = $null
}

# ==================== DEFANGING FUNCTIONS ====================

function ConvertFrom-DefangedIndicator {
    param([string]$Indicator)
    
    if ([string]::IsNullOrEmpty($Indicator)) {
        return $Indicator
    }
    
    # Common refanging
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
    
    # Refang first
    $clean = ConvertFrom-DefangedIndicator -Indicator $Indicator
    
    # Detect type
    if ($clean -match '^https?://') {
        return @{Type="URL"; Value=$clean; Display=$Indicator}
    }
    
    if (Test-IPAddress -IP $clean) {
        return @{Type="IP"; Value=$clean; Display=$Indicator}
    }
    
    # Check if it's a valid domain
    if ($clean -match '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$') {
        return @{Type="Domain"; Value=$clean; Display=$Indicator}
    }
    
    # If it has protocol but not http, could be domain or malformed URL
    if ($clean -match '://') {
        return @{Type="URL"; Value=$clean; Display=$Indicator}
    }
    
    # Default, try as domain
    return @{Type="Domain"; Value=$clean; Display=$Indicator}
}

# ==================== FORMATTING FUNCTIONS ====================

function Write-SectionHeader {
    param(
        [string]$Icon,
        [string]$Title,
        [string]$Status = "Info"
    )
    
    $color = switch ($Status) {
        "Clean"      { "Green" }
        "Suspicious" { "Yellow" }
        "Malicious"  { "Red" }
        default      { "Cyan" }
    }
    
    Write-Host ""
    Write-Host ("─" * 100) -ForegroundColor $color
    Write-Host " $Icon $Title" -ForegroundColor $color
    Write-Host ("─" * 100) -ForegroundColor $color
}

function Write-InfoLine {
    param(
        [string]$Label,
        [string]$Value,
        [string]$Color = "White"
    )
    $paddedLabel = $Label.PadRight(30)
    Write-Host "  $paddedLabel : " -NoNewline -ForegroundColor Gray
    Write-Host $Value -ForegroundColor $Color
}

function Get-ThreatLevel {
    param([int]$MaliciousCount, [int]$TotalCount)
    
    if ($TotalCount -eq 0) { return @("UNKNOWN", "Gray", 0, "Info") }
    
    $percentage = ($MaliciousCount / $TotalCount) * 100
    
    if ($percentage -eq 0) {
        return @("CLEAN", "Green", 0, "Clean")
    } elseif ($percentage -lt 10) {
        return @("SUSPICIOUS", "Yellow", 25, "Suspicious")
    } elseif ($percentage -lt 30) {
        return @("SUSPICIOUS", "Yellow", 50, "Suspicious")
    } else {
        return @("MALICIOUS", "Red", 100, "Malicious")
    }
}

function Get-AbuseLevel {
    param([int]$Score)
    
    if ($Score -eq 0) {
        return @("CLEAN", "Green", "Clean")
    } elseif ($Score -lt 40) {
        return @("LOW RISK", "Green", "Clean")
    } elseif ($Score -lt 75) {
        return @("SUSPICIOUS", "Yellow", "Suspicious")
    } else {
        return @("MALICIOUS", "Red", "Malicious")
    }
}

function Get-FraudLevel {
    param([int]$Score)
    
    if ($Score -eq 0) {
        return @("CLEAN", "Green", "Clean")
    } elseif ($Score -lt 50) {
        return @("LOW RISK", "Green", "Clean")
    } elseif ($Score -lt 75) {
        return @("SUSPICIOUS", "Yellow", "Suspicious")
    } else {
        return @("HIGH RISK", "Red", "Malicious")
    }
}

function Get-PulseLevel {
    param([int]$Count)
    
    if ($Count -eq 0) {
        return @("CLEAN", "Green", "Clean")
    } elseif ($Count -lt 5) {
        return @("SUSPICIOUS", "Yellow", "Suspicious")
    } else {
        return @("MALICIOUS", "Red", "Malicious")
    }
}

function Get-ReputationLevel {
    param([int]$Score)
    
    # VirusTotal reputation score (can be negative)
    if ($Score -ge 0) {
        return @("GOOD", "Green", "Clean")
    } elseif ($Score -ge -10) {
        return @("SUSPICIOUS", "Yellow", "Suspicious")
    } else {
        return @("BAD", "Red", "Malicious")
    }
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

function Format-RDAPDate {
    param([string]$DateString)
    
    if ([string]::IsNullOrEmpty($DateString)) {
        return @($DateString, $null)
    }
    
    try {
        $dt = [DateTime]::Parse($DateString).ToUniversalTime()
        $now = (Get-Date).ToUniversalTime()
        $delta = $now - $dt
        $days = $delta.Days
        
        if ($days -lt 0) {
            return @($dt.ToString("MM/dd/yyyy HH:mm:ss UTC"), "in the future")
        }
        
        $years = [Math]::Floor($days / 365)
        $months = [Math]::Floor(($days % 365) / 30)
        
        if ($years -gt 0) {
            $ago = "$years year$(if($years -gt 1){'s'}) ago"
        } elseif ($months -gt 0) {
            $ago = "$months month$(if($months -gt 1){'s'}) ago"
        } else {
            $ago = "$days day$(if($days -gt 1){'s'}) ago"
        }
        
        return @($dt.ToString("MM/dd/yyyy HH:mm:ss UTC"), $ago)
    } catch {
        return @($DateString, $null)
    }
}

function Get-NormalizedEventAction {
    param([string]$Action)
    
    if ([string]::IsNullOrEmpty($Action)) {
        return "Event"
    }
    
    $mapping = @{
        "registration" = "Registered"
        "last changed" = "Last Modified"
        "last update of rdap database" = "RDAP DB Update"
        "transfer" = "Transferred"
        "expiration" = "Expires"
        "reinstantiation" = "Reinstantiated"
        "deletion" = "Deleted"
    }
    
    $actionLower = $Action.ToLower().Trim()
    if ($mapping.ContainsKey($actionLower)) {
        return $mapping[$actionLower]
    }
    return $Action
}

# ==================== IP ANALYSIS FUNCTIONS ====================

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
    
    try {
        $response = Invoke-WebRequest -Uri $BLACKLIST_URL -TimeoutSec $TIMEOUT -UseBasicParsing
        if ($response.StatusCode -ne 200) {
            $script:BLACKLIST_CACHE.Error = "HTTP $($response.StatusCode)"
            $script:BLACKLIST_CACHE.Loaded = $true
            return
        }
        
        $ipSet = @()
        $lines = $response.Content -split "`n"
        
        foreach ($rawLine in $lines) {
            $line = $rawLine.Trim()
            if ([string]::IsNullOrEmpty($line)) { continue }
            
            if ($line -match '#') {
                $line = ($line -split '#')[0].Trim()
                if ([string]::IsNullOrEmpty($line)) { continue }
            }
            
            $tokens = $line -split '\s+'
            foreach ($token in $tokens) {
                $token = $token.Trim(',;').Trim()
                if ([string]::IsNullOrEmpty($token)) { continue }
                
                if (Test-IPAddress -IP $token) {
                    $ipSet += $token
                }
            }
        }
        
        $script:BLACKLIST_CACHE.IPSet = $ipSet | Select-Object -Unique
        $script:BLACKLIST_CACHE.FetchedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
        $script:BLACKLIST_CACHE.Error = $null
        
    } catch {
        $script:BLACKLIST_CACHE.Error = $_.Exception.Message
    } finally {
        $script:BLACKLIST_CACHE.Loaded = $true
    }
}

function Get-VirusTotalDataIP {
    param([string]$IPAddress)
    
    if ([string]::IsNullOrEmpty($VT_API)) {
        Write-Warning "VirusTotal API key not configured"
        return @{"Status" = "Info"}
    }
    
    try {
        $headers = @{'x-apikey' = $VT_API}
        $response = Invoke-RestMethod -Uri "$URL_VIRUSTOTAL_IP$IPAddress" -Headers $headers -TimeoutSec $TIMEOUT
        
        $data = $response.data.attributes
        $lastAnalysisStats = $data.last_analysis_stats
        
        $maliciousCount = if($lastAnalysisStats.malicious){$lastAnalysisStats.malicious}else{0}
        $totalCount = ($lastAnalysisStats.PSObject.Properties.Value | Measure-Object -Sum).Sum
        
        $threatLevel, $color, $score, $status = Get-ThreatLevel -MaliciousCount $maliciousCount -TotalCount $totalCount
        
        return @{
            "MaliciousCount" = $maliciousCount
            "TotalCount" = $totalCount
            "Community Score" = "$maliciousCount / $totalCount"
            "ThreatLevel" = $threatLevel
            "Status" = $status
            "Security Vendors Flagged" = if($maliciousCount -gt 0){
                "$maliciousCount security vendors flagged this IP address as malicious"
            }else{
                "No security vendors flagged this IP address as malicious"
            }
            "IP" = $IPAddress
            "Network" = $data.network
            "ISP" = "AS $($data.asn) ($($data.as_owner))"
            "Country" = $data.country
            "Region" = $data.regional_internet_registry
            "Continent" = $data.continent
            "Jarm hash" = $data.jarm
            "Last Analysis Date" = if($data.last_analysis_date){Get-DateDifference -Timestamp $data.last_analysis_date}else{$null}
            "Category" = $data.category
            "Reputation" = $data.reputation
        }
        
    } catch {
        Write-Warning "Error querying VirusTotal for $IPAddress : $($_.Exception.Message)"
        return @{"Status" = "Info"}
    }
}

function Get-VirusTotalDataDomain {
    param([string]$Domain)
    
    if ([string]::IsNullOrEmpty($VT_API)) {
        Write-Warning "VirusTotal API key not configured"
        return @{"Status" = "Info"}
    }
    
    try {
        $headers = @{'x-apikey' = $VT_API}
        $response = Invoke-RestMethod -Uri "$URL_VIRUSTOTAL_DOMAIN$Domain" -Headers $headers -TimeoutSec $TIMEOUT
        
        $data = $response.data.attributes
        $lastAnalysisStats = $data.last_analysis_stats
        
        $maliciousCount = if($lastAnalysisStats.malicious){$lastAnalysisStats.malicious}else{0}
        $totalCount = ($lastAnalysisStats.PSObject.Properties.Value | Measure-Object -Sum).Sum
        
        $threatLevel, $color, $score, $status = Get-ThreatLevel -MaliciousCount $maliciousCount -TotalCount $totalCount
        
        return @{
            "MaliciousCount" = $maliciousCount
            "TotalCount" = $totalCount
            "Community Score" = "$maliciousCount / $totalCount"
            "ThreatLevel" = $threatLevel
            "Status" = $status
            "Security Vendors Flagged" = if($maliciousCount -gt 0){
                "$maliciousCount security vendors flagged this domain as malicious"
            }else{
                "No security vendors flagged this domain as malicious"
            }
            "Domain" = $Domain
            "Registrar" = $data.registrar
            "Creation Date" = if($data.creation_date){Get-DateDifference -Timestamp $data.creation_date}else{$null}
            "Last Update Date" = if($data.last_update_date){Get-DateDifference -Timestamp $data.last_update_date}else{$null}
            "Last Analysis Date" = if($data.last_analysis_date){Get-DateDifference -Timestamp $data.last_analysis_date}else{$null}
            "Categories" = ($data.categories.PSObject.Properties.Value | Select-Object -First 5) -join ', '
            "Reputation" = $data.reputation
            "Popularity Rank" = if($data.popularity_ranks.Alexa.rank){"Alexa: $($data.popularity_ranks.Alexa.rank)"}else{"N/A"}
        }
        
    } catch {
        Write-Warning "Error querying VirusTotal for domain $Domain : $($_.Exception.Message)"
        return @{"Status" = "Info"}
    }
}

function Get-VirusTotalDataURL {
    param([string]$URL)
    
    if ([string]::IsNullOrEmpty($VT_API)) {
        Write-Warning "VirusTotal API key not configured"
        return @{"Status" = "Info"}
    }
    
    try {
        $headers = @{'x-apikey' = $VT_API}
        
        # Encode URL in base64
        $urlId = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($URL)) -replace '\+','-' -replace '/','_' -replace '=',''
        
        $response = Invoke-RestMethod -Uri "$URL_VIRUSTOTAL_URL$urlId" -Headers $headers -TimeoutSec $TIMEOUT
        
        $data = $response.data.attributes
        $lastAnalysisStats = $data.last_analysis_stats
        
        $maliciousCount = if($lastAnalysisStats.malicious){$lastAnalysisStats.malicious}else{0}
        $totalCount = ($lastAnalysisStats.PSObject.Properties.Value | Measure-Object -Sum).Sum
        
        $threatLevel, $color, $score, $status = Get-ThreatLevel -MaliciousCount $maliciousCount -TotalCount $totalCount
        
        return @{
            "MaliciousCount" = $maliciousCount
            "TotalCount" = $totalCount
            "Community Score" = "$maliciousCount / $totalCount"
            "ThreatLevel" = $threatLevel
            "Status" = $status
            "Security Vendors Flagged" = if($maliciousCount -gt 0){
                "$maliciousCount security vendors flagged this URL as malicious"
            }else{
                "No security vendors flagged this URL as malicious"
            }
            "URL" = $URL
            "Title" = $data.title
            "Last Analysis Date" = if($data.last_analysis_date){Get-DateDifference -Timestamp $data.last_analysis_date}else{$null}
            "Last HTTP Response Code" = $data.last_http_response_code
            "Categories" = ($data.categories.PSObject.Properties.Value | Select-Object -First 5) -join ', '
            "Reputation" = $data.reputation
        }
        
    } catch {
        Write-Warning "Error querying VirusTotal for URL $URL : $($_.Exception.Message)"
        return @{"Status" = "Info"}
    }
}

function Get-AbuseIPDBData {
    param([string]$IPAddress)
    
    if ([string]::IsNullOrEmpty($ABUSE_API)) {
        Write-Warning "AbuseIPDB API key not configured"
        return @{"Status" = "Info"}
    }
    
    try {
        $headers = @{
            'Accept' = 'application/json'
            'Key' = $ABUSE_API
        }
        $params = @{
            ipAddress = $IPAddress
            maxAgeInDays = 90
        }
        
        $response = Invoke-RestMethod -Uri $URL_ABUSEIPDB -Headers $headers -Body $params -TimeoutSec $TIMEOUT
        $data = $response.data
        
        $isWhitelisted = [bool]$data.isWhitelisted
        $whitelistMsg = if($isWhitelisted){"$IPAddress is whitelisted"}else{"$IPAddress is not whitelisted"}
        
        $abuseLevel, $color, $status = Get-AbuseLevel -Score $data.abuseConfidenceScore
        
        return @{
            "AbuseScore" = $data.abuseConfidenceScore
            "AbuseLevel" = $abuseLevel
            "Status" = $status
            "Whitelist" = $whitelistMsg
            "Reports" = "This IP ($IPAddress) was reported $($data.totalReports) times"
            "TotalReports" = $data.totalReports
            "Confidence of abuse" = "$($data.abuseConfidenceScore)%"
            "ISP" = $data.isp
            "Usage Type" = $data.usageType
            "Country" = $data.countryCode
            "Hostnames" = ($data.hostnames -join ', ')
            "Domain Name" = $data.domain
            "Last Reported" = $data.lastReportedAt
            "TOR" = $data.isTor
        }
        
    } catch {
        Write-Warning "Error querying AbuseIPDB for $IPAddress : $($_.Exception.Message)"
        return @{"Status" = "Info"}
    }
}

function Get-AlienVaultDataIP {
    param([string]$IPAddress)
    
    if ([string]::IsNullOrEmpty($ALIEN_API)) {
        Write-Warning "AlienVault API key not configured"
        return @{"Status" = "Info"}
    }
    
    try {
        $headers = @{'X-OTX-API-KEY' = $ALIEN_API}
        $response = Invoke-RestMethod -Uri "$URL_ALIEN_IP$IPAddress/general" -Headers $headers -TimeoutSec $TIMEOUT
        
        $pulseInfo = $response.pulse_info
        $pulses = $pulseInfo.pulses
        $pulseIds = @()
        
        if ($pulses) {
            foreach ($pulse in $pulses) {
                if ($pulse.id) {
                    $pulseIds += $pulse.id
                }
            }
        }
        
        $pulseLevel, $color, $status = Get-PulseLevel -Count $pulseInfo.count
        
        return @{
            "PulseCount" = $pulseInfo.count
            "PulseLevel" = $pulseLevel
            "Status" = $status
            "IP" = $response.indicator
            "Pulse Info Count" = $pulseInfo.count
            "Pulse Info IDs" = $pulseIds
            "Continent Code" = $response.continent_code
            "Country Code" = $response.country_code2
            "Latitude" = $response.latitude
            "Longitude" = $response.longitude
            "ASN" = $response.asn
        }
        
    } catch {
        Write-Warning "Error querying AlienVault for $IPAddress : $($_.Exception.Message)"
        return @{"Status" = "Info"}
    }
}

function Get-AlienVaultDataDomain {
    param([string]$Domain)
    
    if ([string]::IsNullOrEmpty($ALIEN_API)) {
        Write-Warning "AlienVault API key not configured"
        return @{"Status" = "Info"}
    }
    
    try {
        $headers = @{'X-OTX-API-KEY' = $ALIEN_API}
        $response = Invoke-RestMethod -Uri "$URL_ALIEN_DOMAIN$Domain/general" -Headers $headers -TimeoutSec $TIMEOUT
        
        $pulseInfo = $response.pulse_info
        $pulses = $pulseInfo.pulses
        $pulseIds = @()
        
        if ($pulses) {
            foreach ($pulse in $pulses) {
                if ($pulse.id) {
                    $pulseIds += $pulse.id
                }
            }
        }
        
        $pulseLevel, $color, $status = Get-PulseLevel -Count $pulseInfo.count
        
        return @{
            "PulseCount" = $pulseInfo.count
            "PulseLevel" = $pulseLevel
            "Status" = $status
            "Domain" = $response.indicator
            "Pulse Info Count" = $pulseInfo.count
            "Pulse Info IDs" = $pulseIds
            "Alexa Rank" = $response.alexa
            "Whois" = $response.whois
        }
        
    } catch {
        Write-Warning "Error querying AlienVault for domain $Domain : $($_.Exception.Message)"
        return @{"Status" = "Info"}
    }
}

function Get-AlienVaultDataURL {
    param([string]$URL)
    
    if ([string]::IsNullOrEmpty($ALIEN_API)) {
        Write-Warning "AlienVault API key not configured"
        return @{"Status" = "Info"}
    }
    
    try {
        $headers = @{'X-OTX-API-KEY' = $ALIEN_API}
        $encodedURL = [System.Web.HttpUtility]::UrlEncode($URL)
        $response = Invoke-RestMethod -Uri "$URL_ALIEN_URL$encodedURL/general" -Headers $headers -TimeoutSec $TIMEOUT
        
        $pulseInfo = $response.pulse_info
        $pulses = $pulseInfo.pulses
        $pulseIds = @()
        
        if ($pulses) {
            foreach ($pulse in $pulses) {
                if ($pulse.id) {
                    $pulseIds += $pulse.id
                }
            }
        }
        
        $pulseLevel, $color, $status = Get-PulseLevel -Count $pulseInfo.count
        
        return @{
            "PulseCount" = $pulseInfo.count
            "PulseLevel" = $pulseLevel
            "Status" = $status
            "URL" = $response.indicator
            "Pulse Info Count" = $pulseInfo.count
            "Pulse Info IDs" = $pulseIds
        }
        
    } catch {
        Write-Warning "Error querying AlienVault for URL $URL : $($_.Exception.Message)"
        return @{"Status" = "Info"}
    }
}

function Get-IPQualityScoreDataIP {
    param(
        [string]$IPAddress,
        [int]$Strictness = 1,
        [bool]$Fast = $true
    )
    
    if ([string]::IsNullOrEmpty($IPQ_API)) {
        return @{"Status" = "Info"}
    }
    
    try {
        $url = "$URL_IPQ_IP$IPQ_API/$IPAddress"
        $params = @{
            strictness = $Strictness
            fast = if($Fast){"true"}else{"false"}
            allow_public_access_points = "true"
            lighter_penalties = "true"
        }
        
        $response = Invoke-RestMethod -Uri $url -Body $params -TimeoutSec $TIMEOUT
        
        $fraudLevel, $color, $status = Get-FraudLevel -Score $response.fraud_score
        
        return @{
            "FraudScore" = $response.fraud_score
            "FraudLevel" = $fraudLevel
            "Status" = $status
            "Fraud Score" = $response.fraud_score
            "Proxy" = $response.proxy
            "TOR" = $response.tor
            "Recent Abuse" = $response.recent_abuse
            "ISP" = $response.ISP
            "Organization" = if($response.organization){$response.organization}else{$response.Organization}
            "ASN" = $response.ASN
            "Country Code" = $response.country_code
            "City" = $response.city
            "Region" = $response.region
        }
        
    } catch {
        Write-Warning "Error querying IPQualityScore for $IPAddress : $($_.Exception.Message)"
        return @{"Status" = "Info"}
    }
}

function Get-IPQualityScoreDataURL {
    param([string]$URL, [int]$Strictness = 1)
    
    if ([string]::IsNullOrEmpty($IPQ_API)) {
        return @{"Status" = "Info"}
    }
    
    try {
        $apiUrl = "$URL_IPQ_URL$IPQ_API"
        $params = @{
            url = $URL
            strictness = $Strictness
        }
        
        $response = Invoke-RestMethod -Uri $apiUrl -Body $params -TimeoutSec $TIMEOUT
        
        $riskScore = if($response.risk_score){$response.risk_score}else{0}
        $fraudLevel, $color, $status = Get-FraudLevel -Score $riskScore
        
        return @{
            "RiskScore" = $riskScore
            "RiskLevel" = $fraudLevel
            "Status" = $status
            "Risk Score" = $riskScore
            "Suspicious" = $response.suspicious
            "Phishing" = $response.phishing
            "Malware" = $response.malware
            "Parking" = $response.parking
            "Spamming" = $response.spamming
            "Adult" = $response.adult
            "Domain Age" = $response.domain_age
            "Domain Rank" = $response.domain_rank
            "Category" = $response.category
        }
        
    } catch {
        Write-Warning "Error querying IPQualityScore for URL $URL : $($_.Exception.Message)"
        return @{"Status" = "Info"}
    }
}

function Get-URLScanData {
    param([string]$URL)
    
    if ([string]::IsNullOrEmpty($URLSCAN_API)) {
        return @{"Status" = "Info"}
    }
    
    try {
        # Search for existing scan
        $headers = @{'API-Key' = $URLSCAN_API}
        $searchUrl = "$URL_URLSCAN/search/?q=page.url:`"$URL`""
        
        $response = Invoke-RestMethod -Uri $searchUrl -Headers $headers -TimeoutSec $TIMEOUT
        
        if ($response.results -and $response.results.Count -gt 0) {
            $result = $response.results[0]
            
            $verdictScore = if($result.verdicts.overall.score){$result.verdicts.overall.score}else{0}
            $fraudLevel, $color, $status = Get-FraudLevel -Score $verdictScore
            
            return @{
                "Status" = $status
                "VerdictScore" = $verdictScore
                "VerdictLevel" = $fraudLevel
                "Overall Score" = $verdictScore
                "Malicious" = $result.verdicts.overall.malicious
                "Categories" = ($result.verdicts.overall.categories -join ', ')
                "Page Title" = $result.page.title
                "Domain" = $result.page.domain
                "Country" = $result.page.country
                "IP" = $result.page.ip
                "Result URL" = $result.result
            }
        }
        
        return @{"Status" = "Info"; "Message" = "No previous scans found"}
        
    } catch {
        Write-Warning "Error querying URLScan for $URL : $($_.Exception.Message)"
        return @{"Status" = "Info"}
    }
}

function Get-RDAPData {
    param([string]$IPAddress)
    
    $headers = @{'Accept' = 'application/rdap+json, application/json'}
    $lastError = $null
    
    foreach ($endpoint in $RDAP_ENDPOINTS) {
        $url = "$($endpoint.URL)$IPAddress"
        
        try {
            $response = Invoke-RestMethod -Uri $url -Headers $headers -TimeoutSec $TIMEOUT -ErrorAction Stop
            
            $startAddr = $response.startAddress
            $endAddr = $response.endAddress
            $cidr = "$startAddr - $endAddr"
            $contacts = Get-RDAPContacts -Entities $response.entities
            
            $owner = $null
            foreach ($bucket in @('registrant','other','administrative','technical','abuse')) {
                if ($contacts[$bucket] -and $contacts[$bucket].Count -gt 0) {
                    $c = $contacts[$bucket][0]
                    $owner = if($c.org){$c.org}elseif($c.name){$c.name}
                    if ($owner) { break }
                }
            }
            
            $events = Get-EventsSummary -Events $response.events
            
            $link = $null
            if ($response.links) {
                foreach ($l in $response.links) {
                    if ($l.href) {
                        $link = $l.href
                        break
                    }
                }
            }
            
            return @{
                "Status" = "Info"
                "RIR" = $endpoint.Name
                "Handle" = $response.handle
                "Name" = $response.name
                "IP Version" = $response.ipVersion
                "Country" = $response.country
                "Start Address" = $startAddr
                "End Address" = $endAddr
                "CIDR" = $cidr
                "Owner (heuristic)" = $owner
                "Events" = $events
                "Reference" = $link
                "RDAP Contacts" = $contacts
            }
            
        } catch {
            if ($_.Exception.Response.StatusCode.Value__ -eq 404) {
                continue
            }
            $lastError = "$($endpoint.Name) - $($_.Exception.Message)"
            continue
        }
    }
    
    if ($lastError) {
        return @{"RDAP Error" = "No RDAP provider returned data. Last error: $lastError"; "Status" = "Info"}
    }
    return @{"RDAP Error" = "No RDAP provider returned data (unknown error)"; "Status" = "Info"}
}

function Get-RDAPContacts {
    param($Entities)
    
    $contacts = @{
        abuse = @()
        technical = @()
        administrative = @()
        registrant = @()
        other = @()
    }
    
    if (-not $Entities) { return $contacts }
    
    foreach ($ent in $Entities) {
        if (-not $ent) { continue }
        
        $roles = @()
        if ($ent.roles) {
            $roles = $ent.roles | ForEach-Object { $_.ToLower() }
        }
        
        $vcard = Get-VCardData -VCardArray $ent.vcardArray
        
        $contact = @{
            handle = $ent.handle
            roles = $roles
            name = $vcard.fn
            org = $vcard.org
            emails = $vcard.emails
            phones = $vcard.phones
            addresses = $vcard.addresses
        }
        
        if ($roles -contains "abuse") {
            $contacts.abuse += $contact
        } elseif ($roles -contains "technical") {
            $contacts.technical += $contact
        } elseif ($roles -contains "administrative" -or $roles -contains "admin") {
            $contacts.administrative += $contact
        } elseif ($roles -contains "registrant") {
            $contacts.registrant += $contact
        } else {
            $contacts.other += $contact
        }
    }
    
    return $contacts
}

function Get-VCardData {
    param($VCardArray)
    
    $result = @{
        fn = $null
        org = $null
        emails = @()
        phones = @()
        addresses = @()
    }
    
    if (-not $VCardArray -or $VCardArray.Count -lt 2) {
        return $result
    }
    
    $items = $VCardArray[1]
    if (-not $items) { return $result }
    
    foreach ($item in $items) {
        if (-not $item -or $item.Count -lt 4) { continue }
        
        $key = $item[0]
        $value = $item[3]
        
        switch ($key) {
            "fn" { 
                if ($value -is [string]) {
                    $result.fn = $value 
                }
            }
            "org" {
                if ($value -is [string]) {
                    $result.org = $value
                } elseif ($value -is [array] -and $value.Count -gt 0) {
                    $result.org = [string]$value[0]
                }
            }
            "email" {
                if ($value -is [string] -and $value -notin $result.emails) {
                    $result.emails += $value
                }
            }
            "tel" {
                if ($value -is [string] -and $value -notin $result.phones) {
                    $result.phones += $value
                }
            }
            "adr" {
                $addr = ""
                if ($value -is [array]) {
                    $addr = ($value | Where-Object {$_}) -join " "
                } else {
                    $addr = [string]$value
                }
                if ($addr -and $addr -notin $result.addresses) {
                    $result.addresses += $addr
                }
            }
        }
    }
    
    return $result
}

function Get-EventsSummary {
    param($Events, [int]$MaxEvents = 5)
    
    $out = @()
    if (-not $Events) { return $out }
    
    foreach ($e in $Events) {
        if (-not $e) { continue }
        
        $actionRaw = $e.eventAction
        $dateRaw = $e.eventDate
        
        if (-not $actionRaw -and -not $dateRaw) { continue }
        
        $action = Get-NormalizedEventAction -Action $actionRaw
        $datePretty, $ago = Format-RDAPDate -DateString $dateRaw
        
        $epochPlaceholder = $dateRaw -and $dateRaw.StartsWith("1970-01-01")
        
        if ($epochPlaceholder) {
            $out += "$action : $datePretty (placeholder / unreliable date)"
        } elseif ($ago) {
            $out += "$action : $datePretty ($ago)"
        } else {
            $out += "$action : $datePretty"
        }
    }
    
    return $out | Select-Object -First $MaxEvents
}

# ==================== OUTPUT FUNCTIONS ====================

function Write-ThreatSummary {
    param(
        [string]$Type,
        [hashtable]$VTData,
        [hashtable]$AbuseData,
        [hashtable]$AlienData,
        [hashtable]$IPQData,
        [hashtable]$BlacklistData,
        [hashtable]$URLScanData
    )
    
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                              THREAT SUMMARY                                                   ║" -ForegroundColor White -BackgroundColor DarkCyan
    Write-Host "╚═══════════════════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    # VirusTotal
    $malCount = if($VTData.MaliciousCount){$VTData.MaliciousCount}else{0}
    $totalCount = if($VTData.TotalCount){$VTData.TotalCount}else{1}
    $threatLevel = if($VTData.ThreatLevel){$VTData.ThreatLevel}else{"UNKNOWN"}
    $vtStatus = if($VTData.Status){$VTData.Status}else{"Info"}
    
    $color = switch ($vtStatus) {
        "Clean"      { "Green" }
        "Suspicious" { "Yellow" }
        "Malicious"  { "Red" }
        default      { "White" }
    }
    
    $icon = switch ($vtStatus) {
        "Clean"      { "✓" }
        "Suspicious" { "⚠" }
        "Malicious"  { "✖" }
        default      { "ℹ" }
    }
    
    Write-Host ""
    Write-Host "  $icon VirusTotal                 : " -NoNewline -ForegroundColor $color
    Write-Host "$malCount / $totalCount vendors flagged" -NoNewline -ForegroundColor White
    Write-Host " [$threatLevel]" -ForegroundColor $color
    
    # AbuseIPDB (IP only)
    if ($Type -eq "IP" -and $AbuseData.Count -gt 0) {
        $abuseScore = if($AbuseData.AbuseScore){$AbuseData.AbuseScore}else{0}
        $abuseLevel = if($AbuseData.AbuseLevel){$AbuseData.AbuseLevel}else{"UNKNOWN"}
        $abuseStatus = if($AbuseData.Status){$AbuseData.Status}else{"Info"}
        $reportCount = if($AbuseData.TotalReports){$AbuseData.TotalReports}else{0}
        
        $color = switch ($abuseStatus) {
            "Clean"      { "Green" }
            "Suspicious" { "Yellow" }
            "Malicious"  { "Red" }
            default      { "White" }
        }
        
        $icon = switch ($abuseStatus) {
            "Clean"      { "✓" }
            "Suspicious" { "⚠" }
            "Malicious"  { "✖" }
            default      { "ℹ" }
        }
        
        Write-Host "  $icon AbuseIPDB                 : " -NoNewline -ForegroundColor $color
        Write-Host "$reportCount reports | Confidence: $abuseScore%" -NoNewline -ForegroundColor White
        Write-Host " [$abuseLevel]" -ForegroundColor $color
    }
    
    # AlienVault
    $pulseCount = if($AlienData.PulseCount){$AlienData.PulseCount}else{0}
    $pulseLevel = if($AlienData.PulseLevel){$AlienData.PulseLevel}else{"UNKNOWN"}
    $alienStatus = if($AlienData.Status){$AlienData.Status}else{"Info"}
    
    $color = switch ($alienStatus) {
        "Clean"      { "Green" }
        "Suspicious" { "Yellow" }
        "Malicious"  { "Red" }
        default      { "White" }
    }
    
    $icon = switch ($alienStatus) {
        "Clean"      { "✓" }
        "Suspicious" { "⚠" }
        "Malicious"  { "✖" }
        default      { "ℹ" }
    }
    
    Write-Host "  $icon AlienVault OTX            : " -NoNewline -ForegroundColor $color
    Write-Host "$pulseCount pulses found" -NoNewline -ForegroundColor White
    Write-Host " [$pulseLevel]" -ForegroundColor $color
    
    # IPQualityScore
    if ($Type -eq "IP") {
        $fraudScore = if($IPQData.FraudScore){$IPQData.FraudScore}else{0}
        $fraudLevel = if($IPQData.FraudLevel){$IPQData.FraudLevel}else{"UNKNOWN"}
        $ipqStatus = if($IPQData.Status){$IPQData.Status}else{"Info"}
        $torStatus = if($IPQData.TOR){"Yes"}else{"No"}
        
        $color = switch ($ipqStatus) {
            "Clean"      { "Green" }
            "Suspicious" { "Yellow" }
            "Malicious"  { "Red" }
            default      { "White" }
        }
        
        $icon = switch ($ipqStatus) {
            "Clean"      { "✓" }
            "Suspicious" { "⚠" }
            "Malicious"  { "✖" }
            default      { "ℹ" }
        }
        
        Write-Host "  $icon IPQualityScore            : " -NoNewline -ForegroundColor $color
        Write-Host "Fraud Score: $fraudScore | TOR: $torStatus" -NoNewline -ForegroundColor White
        Write-Host " [$fraudLevel]" -ForegroundColor $color
    } elseif ($Type -eq "URL") {
        $riskScore = if($IPQData.RiskScore){$IPQData.RiskScore}else{0}
        $riskLevel = if($IPQData.RiskLevel){$IPQData.RiskLevel}else{"UNKNOWN"}
        $ipqStatus = if($IPQData.Status){$IPQData.Status}else{"Info"}
        
        $color = switch ($ipqStatus) {
            "Clean"      { "Green" }
            "Suspicious" { "Yellow" }
            "Malicious"  { "Red" }
            default      { "White" }
        }
        
        $icon = switch ($ipqStatus) {
            "Clean"      { "✓" }
            "Suspicious" { "⚠" }
            "Malicious"  { "✖" }
            default      { "ℹ" }
        }
        
        Write-Host "  $icon IPQualityScore            : " -NoNewline -ForegroundColor $color
        Write-Host "Risk Score: $riskScore" -NoNewline -ForegroundColor White
        Write-Host " [$riskLevel]" -ForegroundColor $color
    }
    
    # URLScan (URL only)
    if ($Type -eq "URL" -and $URLScanData.ContainsKey("VerdictScore")) {
        $verdictScore = $URLScanData.VerdictScore
        $verdictLevel = $URLScanData.VerdictLevel
        $urlscanStatus = $URLScanData.Status
        
        $color = switch ($urlscanStatus) {
            "Clean"      { "Green" }
            "Suspicious" { "Yellow" }
            "Malicious"  { "Red" }
            default      { "White" }
        }
        
        $icon = switch ($urlscanStatus) {
            "Clean"      { "✓" }
            "Suspicious" { "⚠" }
            "Malicious"  { "✖" }
            default      { "ℹ" }
        }
        
        Write-Host "  $icon URLScan.io                : " -NoNewline -ForegroundColor $color
        Write-Host "Verdict Score: $verdictScore" -NoNewline -ForegroundColor White
        Write-Host " [$verdictLevel]" -ForegroundColor $color
    }
    
    # Blacklist (IP only)
    if ($Type -eq "IP" -and $BlacklistData.Count -gt 0) {
        $isBlacklisted = $BlacklistData.Blacklist -eq "Yes"
        $blStatus = if($BlacklistData.Status){$BlacklistData.Status}else{"Info"}
        
        $color = switch ($blStatus) {
            "Clean"      { "Green" }
            "Suspicious" { "Yellow" }
            "Malicious"  { "Red" }
            default      { "White" }
        }
        
        $icon = switch ($blStatus) {
            "Clean"      { "✓" }
            "Suspicious" { "⚠" }
            "Malicious"  { "✖" }
            default      { "ℹ" }
        }
        
        Write-Host "  $icon Blacklist Custom         : " -NoNewline -ForegroundColor $color
        Write-Host $BlacklistData.Blacklist -ForegroundColor White
    }
    
    Write-Host ""
    Write-Host ("═" * 100) -ForegroundColor Cyan
}

function Write-VirusTotalSection {
    param([hashtable]$Data, [string]$Type)
    
    if ($Data.Count -eq 0 -or -not $Data.ContainsKey("Community Score")) {
        Write-SectionHeader -Icon "🛡️ " -Title "VIRUSTOTAL" -Status "Info"
        Write-Host "`n  ⓘ VirusTotal data not available" -ForegroundColor DarkGray
        return
    }
    
    $status = if($Data.Status){$Data.Status}else{"Info"}
    Write-SectionHeader -Icon "🛡️ " -Title "VIRUSTOTAL" -Status $status
    
    Write-InfoLine -Label "Detection Ratio" -Value $Data['Community Score'] -Color "Cyan"
    Write-InfoLine -Label "Security Vendors" -Value $Data['Security Vendors Flagged']
    Write-InfoLine -Label "Reputation Score" -Value $Data['Reputation']
    Write-InfoLine -Label "Last Analysis" -Value $Data['Last Analysis Date']
    
    if ($Type -eq "IP") {
        Write-Host ""
        Write-Host "  Network Information:" -ForegroundColor Yellow
        Write-InfoLine -Label "  ISP" -Value $Data['ISP']
        Write-InfoLine -Label "  Network Range" -Value $Data['Network']
        Write-InfoLine -Label "  Country" -Value $Data['Country']
        Write-InfoLine -Label "  Region" -Value $Data['Region']
        Write-InfoLine -Label "  Continent" -Value $Data['Continent']
        
        if ($Data['Jarm hash']) {
            Write-Host ""
            Write-InfoLine -Label "JARM Fingerprint" -Value $Data['Jarm hash'] -Color "DarkGray"
        }
    } elseif ($Type -eq "Domain") {
        Write-Host ""
        Write-Host "  Domain Information:" -ForegroundColor Yellow
        Write-InfoLine -Label "  Registrar" -Value $Data['Registrar']
        Write-InfoLine -Label "  Creation Date" -Value $Data['Creation Date']
        Write-InfoLine -Label "  Last Update" -Value $Data['Last Update Date']
        Write-InfoLine -Label "  Categories" -Value $Data['Categories']
        Write-InfoLine -Label "  Popularity" -Value $Data['Popularity Rank']
    } elseif ($Type -eq "URL") {
        Write-Host ""
        Write-Host "  URL Information:" -ForegroundColor Yellow
        Write-InfoLine -Label "  Title" -Value $Data['Title']
        Write-InfoLine -Label "  HTTP Code" -Value $Data['Last HTTP Response Code']
        Write-InfoLine -Label "  Categories" -Value $Data['Categories']
    }
}

function Write-AbuseIPDBSection {
    param([hashtable]$Data)
    
    if ($Data.Count -eq 0 -or -not $Data.ContainsKey("Confidence of abuse")) {
        Write-SectionHeader -Icon "🚨" -Title "ABUSEIPDB" -Status "Info"
        Write-Host "`n  ⓘ AbuseIPDB data not available (IP only)" -ForegroundColor DarkGray
        return
    }
    
    $status = if($Data.Status){$Data.Status}else{"Info"}
    Write-SectionHeader -Icon "🚨" -Title "ABUSEIPDB" -Status $status
    
    $score = if($Data.AbuseScore){$Data.AbuseScore}else{0}
    $scoreColor = switch ($status) {
        "Clean"      { "Green" }
        "Suspicious" { "Yellow" }
        "Malicious"  { "Red" }
        default      { "White" }
    }
    
    Write-InfoLine -Label "Abuse Confidence Score" -Value "$score%" -Color $scoreColor
    Write-InfoLine -Label "Total Reports (90 days)" -Value $Data.TotalReports
    Write-InfoLine -Label "Last Reported" -Value $Data['Last Reported']
    Write-InfoLine -Label "Whitelist Status" -Value $Data.Whitelist
    
    Write-Host ""
    Write-Host "  Network Details:" -ForegroundColor Yellow
    Write-InfoLine -Label "  ISP" -Value $Data.ISP
    Write-InfoLine -Label "  Usage Type" -Value $Data['Usage Type']
    Write-InfoLine -Label "  Country" -Value $Data.Country
    Write-InfoLine -Label "  Domain" -Value $Data['Domain Name']
    
    if ($Data.Hostnames) {
        Write-InfoLine -Label "  Hostnames" -Value $Data.Hostnames
    }
    
    $torStatus = if($Data.TOR){"Yes (TOR Exit Node)"}else{"No"}
    $torColor = if($Data.TOR){"Red"}else{"Green"}
    Write-InfoLine -Label "  TOR Node" -Value $torStatus -Color $torColor
}

function Write-AlienVaultSection {
    param([hashtable]$Data, [string]$Type)
    
    if ($Data.Count -eq 0 -or -not $Data.ContainsKey("Pulse Info Count")) {
        Write-SectionHeader -Icon "👽" -Title "ALIENVAULT OTX" -Status "Info"
        Write-Host "`n  ⓘ AlienVault OTX data not available" -ForegroundColor DarkGray
        return
    }
    
    $status = if($Data.Status){$Data.Status}else{"Info"}
    Write-SectionHeader -Icon "👽" -Title "ALIENVAULT OTX" -Status $status
    
    $pulseCount = if($Data['Pulse Info Count']){$Data['Pulse Info Count']}else{0}
    $pulseColor = switch ($status) {
        "Clean"      { "Green" }
        "Suspicious" { "Yellow" }
        "Malicious"  { "Red" }
        default      { "White" }
    }
    
    Write-InfoLine -Label "Threat Pulses" -Value $pulseCount -Color $pulseColor
    
    if ($Data['Pulse Info IDs'] -and $Data['Pulse Info IDs'].Count -gt 0) {
        Write-Host ""
        Write-Host "  Pulse IDs (showing first 5):" -ForegroundColor Yellow
        $displayIds = $Data['Pulse Info IDs'] | Select-Object -First 5
        foreach ($id in $displayIds) {
            Write-Host "    • $id" -ForegroundColor Cyan
        }
    }
    
    if ($Type -eq "IP") {
        Write-Host ""
        Write-Host "  Geolocation:" -ForegroundColor Yellow
        Write-InfoLine -Label "  Country Code" -Value $Data['Country Code']
        Write-InfoLine -Label "  Continent" -Value $Data['Continent Code']
        Write-InfoLine -Label "  Coordinates" -Value "Lat: $($Data.Latitude), Lon: $($Data.Longitude)"
        Write-InfoLine -Label "  ASN" -Value $Data.ASN
    } elseif ($Type -eq "Domain") {
        if ($Data['Alexa Rank']) {
            Write-Host ""
            Write-InfoLine -Label "Alexa Rank" -Value $Data['Alexa Rank']
        }
    }
}

function Write-IPQualityScoreSection {
    param([hashtable]$Data, [string]$Type)
    
    if ($Data.Count -eq 0) {
        Write-SectionHeader -Icon "🔍" -Title "IPQUALITYSCORE" -Status "Info"
        Write-Host "`n  ⓘ IPQualityScore data not available" -ForegroundColor DarkGray
        return
    }
    
    $status = if($Data.Status){$Data.Status}else{"Info"}
    Write-SectionHeader -Icon "🔍" -Title "IPQUALITYSCORE" -Status $status
    
    if ($Type -eq "IP") {
        $fraudScore = if($Data['Fraud Score']){$Data['Fraud Score']}else{0}
        $fraudColor = switch ($status) {
            "Clean"      { "Green" }
            "Suspicious" { "Yellow" }
            "Malicious"  { "Red" }
            default      { "White" }
        }
        
        Write-InfoLine -Label "Fraud Score" -Value "$fraudScore / 100" -Color $fraudColor
        
        $proxyStatus = if($Data.Proxy){"Yes"}else{"No"}
        $proxyColor = if($Data.Proxy){"Red"}else{"Green"}
        Write-InfoLine -Label "Proxy Detected" -Value $proxyStatus -Color $proxyColor
        
        $torStatus = if($Data.TOR){"Yes"}else{"No"}
        $torColor = if($Data.TOR){"Red"}else{"Green"}
        Write-InfoLine -Label "TOR Exit Node" -Value $torStatus -Color $torColor
        
        $abuseStatus = if($Data['Recent Abuse']){"Yes"}else{"No"}
        $abuseColor = if($Data['Recent Abuse']){"Red"}else{"Green"}
        Write-InfoLine -Label "Recent Abuse" -Value $abuseStatus -Color $abuseColor
        
        Write-Host ""
        Write-Host "  Organization:" -ForegroundColor Yellow
        Write-InfoLine -Label "  ISP" -Value $Data.ISP
        Write-InfoLine -Label "  Organization" -Value $Data.Organization
        Write-InfoLine -Label "  ASN" -Value $Data.ASN
        
        Write-Host ""
        Write-Host "  Location:" -ForegroundColor Yellow
        Write-InfoLine -Label "  Country" -Value $Data['Country Code']
        Write-InfoLine -Label "  Region" -Value $Data.Region
        Write-InfoLine -Label "  City" -Value $Data.City
    } elseif ($Type -eq "URL") {
        $riskScore = if($Data['Risk Score']){$Data['Risk Score']}else{0}
        $riskColor = switch ($status) {
            "Clean"      { "Green" }
            "Suspicious" { "Yellow" }
            "Malicious"  { "Red" }
            default      { "White" }
        }
        
        Write-InfoLine -Label "Risk Score" -Value "$riskScore / 100" -Color $riskColor
        
        $phishingStatus = if($Data.Phishing){"Yes"}else{"No"}
        $phishingColor = if($Data.Phishing){"Red"}else{"Green"}
        Write-InfoLine -Label "Phishing" -Value $phishingStatus -Color $phishingColor
        
        $malwareStatus = if($Data.Malware){"Yes"}else{"No"}
        $malwareColor = if($Data.Malware){"Red"}else{"Green"}
        Write-InfoLine -Label "Malware" -Value $malwareStatus -Color $malwareColor
        
        $suspiciousStatus = if($Data.Suspicious){"Yes"}else{"No"}
        $suspiciousColor = if($Data.Suspicious){"Yellow"}else{"Green"}
        Write-InfoLine -Label "Suspicious" -Value $suspiciousStatus -Color $suspiciousColor
        
        Write-Host ""
        Write-Host "  Domain Information:" -ForegroundColor Yellow
        Write-InfoLine -Label "  Domain Age" -Value "$($Data['Domain Age']) days"
        Write-InfoLine -Label "  Domain Rank" -Value $Data['Domain Rank']
        Write-InfoLine -Label "  Category" -Value $Data.Category
        Write-InfoLine -Label "  Parking" -Value $(if($Data.Parking){"Yes"}else{"No"})
        Write-InfoLine -Label "  Spamming" -Value $(if($Data.Spamming){"Yes"}else{"No"})
        Write-InfoLine -Label "  Adult Content" -Value $(if($Data.Adult){"Yes"}else{"No"})
    }
}

function Write-URLScanSection {
    param([hashtable]$Data)
    
    if ($Data.Count -eq 0 -or -not $Data.ContainsKey("VerdictScore")) {
        Write-SectionHeader -Icon "🔎" -Title "URLSCAN.IO" -Status "Info"
        Write-Host "`n  ⓘ URLScan.io data not available or no previous scans" -ForegroundColor DarkGray
        return
    }
    
    $status = if($Data.Status){$Data.Status}else{"Info"}
    Write-SectionHeader -Icon "🔎" -Title "URLSCAN.IO" -Status $status
    
    $verdictScore = $Data['Overall Score']
    $scoreColor = switch ($status) {
        "Clean"      { "Green" }
        "Suspicious" { "Yellow" }
        "Malicious"  { "Red" }
        default      { "White" }
    }
    
    Write-InfoLine -Label "Verdict Score" -Value "$verdictScore / 100" -Color $scoreColor
    
    $maliciousStatus = if($Data.Malicious){"Yes"}else{"No"}
    $maliciousColor = if($Data.Malicious){"Red"}else{"Green"}
    Write-InfoLine -Label "Malicious" -Value $maliciousStatus -Color $maliciousColor
    
    if ($Data.Categories) {
        Write-InfoLine -Label "Categories" -Value $Data.Categories
    }
    
    Write-Host ""
    Write-Host "  Page Information:" -ForegroundColor Yellow
    Write-InfoLine -Label "  Title" -Value $Data['Page Title']
    Write-InfoLine -Label "  Domain" -Value $Data.Domain
    Write-InfoLine -Label "  IP" -Value $Data.IP
    Write-InfoLine -Label "  Country" -Value $Data.Country
    
    if ($Data['Result URL']) {
        Write-Host ""
        Write-InfoLine -Label "Scan Result" -Value $Data['Result URL'] -Color "Cyan"
    }
}

function Write-RDAPSection {
    param([hashtable]$Data)
    
    if ($Data.ContainsKey("RDAP Error")) {
        Write-SectionHeader -Icon "📋" -Title "RDAP (Registration Data Access Protocol)" -Status "Info"
        Write-Host "`n  ⚠ RDAP Error: $($Data['RDAP Error'])" -ForegroundColor Yellow
        return
    }
    
    $status = if($Data.Status){$Data.Status}else{"Info"}
    Write-SectionHeader -Icon "📋" -Title "RDAP (Registration Data Access Protocol)" -Status $status
    
    Write-InfoLine -Label "RIR" -Value $Data.RIR -Color "Cyan"
    Write-InfoLine -Label "Handle" -Value $Data.Handle
    Write-InfoLine -Label "Name" -Value $Data.Name
    Write-InfoLine -Label "IP Version" -Value "IPv$($Data['IP Version'])"
    Write-InfoLine -Label "Country" -Value $Data.Country
    
    Write-Host ""
    Write-Host "  IP Range:" -ForegroundColor Yellow
    Write-InfoLine -Label "  Start Address" -Value $Data['Start Address']
    Write-InfoLine -Label "  End Address" -Value $Data['End Address']
    Write-InfoLine -Label "  CIDR" -Value $Data.CIDR
    
    if ($Data['Owner (heuristic)']) {
        Write-Host ""
        Write-InfoLine -Label "Owner" -Value $Data['Owner (heuristic)'] -Color "Cyan"
    }
    
    if ($Data.Events -and $Data.Events.Count -gt 0) {
        Write-Host ""
        Write-Host "  Registration Events:" -ForegroundColor Yellow
        foreach ($event in $Data.Events) {
            Write-Host "    • $event" -ForegroundColor White
        }
    }
    
    if ($Data.Reference) {
        Write-Host ""
        Write-InfoLine -Label "Reference URL" -Value $Data.Reference -Color "DarkGray"
    }
    
    if ($Data['RDAP Contacts']) {
        Write-Host ""
        Write-Host "  Contacts:" -ForegroundColor Yellow
        
        $contacts = $Data['RDAP Contacts']
        
        if ($contacts.abuse -and $contacts.abuse.Count -gt 0) {
            Write-Host "    Abuse:" -ForegroundColor Red
            foreach ($c in $contacts.abuse) {
                $info = if($c.org){$c.org}elseif($c.name){$c.name}else{"N/A"}
                if ($c.emails -and $c.emails.Count -gt 0) {
                    $info += " | $($c.emails[0])"
                }
                Write-Host "      • $info" -ForegroundColor White
            }
        }
        
        if ($contacts.technical -and $contacts.technical.Count -gt 0) {
            Write-Host "    Technical:" -ForegroundColor Cyan
            foreach ($c in $contacts.technical) {
                $info = if($c.org){$c.org}elseif($c.name){$c.name}else{"N/A"}
                if ($c.emails -and $c.emails.Count -gt 0) {
                    $info += " | $($c.emails[0])"
                }
                Write-Host "      • $info" -ForegroundColor White
            }
        }
        
        if ($contacts.administrative -and $contacts.administrative.Count -gt 0) {
            Write-Host "    Administrative:" -ForegroundColor Yellow
            foreach ($c in $contacts.administrative) {
                $info = if($c.org){$c.org}elseif($c.name){$c.name}else{"N/A"}
                if ($c.emails -and $c.emails.Count -gt 0) {
                    $info += " | $($c.emails[0])"
                }
                Write-Host "      • $info" -ForegroundColor White
            }
        }
    }
}

function Write-BlacklistSection {
    param([hashtable]$Data)
    
    if ($Data.Blacklist -eq "Error") {
        Write-SectionHeader -Icon "🚫" -Title "CUSTOM BLACKLIST" -Status "Info"
        Write-Host "  ⚠ Error: $($Data['Blacklist Error'])" -ForegroundColor Red
        return
    }
    
    $status = if($Data.Status){$Data.Status}else{"Info"}
    Write-SectionHeader -Icon "🚫" -Title "CUSTOM BLACKLIST" -Status $status
    
    $isBlacklisted = $Data.Blacklist -eq "Yes"
    $color = switch ($status) {
        "Clean"      { "Green" }
        "Suspicious" { "Yellow" }
        "Malicious"  { "Red" }
        default      { "White" }
    }
    $statusText = if($isBlacklisted){"BLACKLISTED ✖"}else{"CLEAN ✓"}
    
    Write-InfoLine -Label "Status" -Value $statusText -Color $color
    
    if ($Data['Blacklist Checked']) {
        Write-InfoLine -Label "Last Updated" -Value $Data['Blacklist Checked'] -Color "DarkGray"
    }
}

function Write-ResultsToConsole {
    param(
        [string]$Target,
        [string]$Type,
        [string]$DisplayValue
    )
    
    # Main banner
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    $title = switch ($Type) {
        "IP"     { "IP REPUTATION ANALYSIS REPORT" }
        "Domain" { "DOMAIN REPUTATION ANALYSIS REPORT" }
        "URL"    { "URL REPUTATION ANALYSIS REPORT" }
    }
    Write-Host "║                           $($title.PadRight(59))║" -ForegroundColor White -BackgroundColor DarkCyan
    Write-Host "╠═══════════════════════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║  Target ($Type): $($Target.PadRight(76)) ║" -ForegroundColor White
    if ($DisplayValue -ne $Target) {
        Write-Host "║  Original Input: $($DisplayValue.PadRight(75)) ║" -ForegroundColor Yellow
    }
    Write-Host "║  Analysis Date: $((Get-Date).ToString('MM/dd/yyyy HH:mm:ss').PadRight(74)) ║" -ForegroundColor White
    Write-Host "╚═══════════════════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    # Collect data
    Write-Host "`n  ⏳ Querying threat intelligence providers..." -ForegroundColor Yellow
    
    $vtData = @{"Status" = "Info"}
    $abuseData = @{}
    $alienData = @{"Status" = "Info"}
    $ipqsData = @{"Status" = "Info"}
    $rdapData = @{}
    $blacklistData = @{}
    $urlscanData = @{}
    
    if ($Type -eq "IP") {
        $vtData = Get-VirusTotalDataIP -IPAddress $Target
        $abuseData = Get-AbuseIPDBData -IPAddress $Target
        $alienData = Get-AlienVaultDataIP -IPAddress $Target
        $ipqsData = Get-IPQualityScoreDataIP -IPAddress $Target
        $rdapData = Get-RDAPData -IPAddress $Target
        $blacklistData = Get-BlacklistData -IPAddress $Target
    } elseif ($Type -eq "Domain") {
        $vtData = Get-VirusTotalDataDomain -Domain $Target
        $alienData = Get-AlienVaultDataDomain -Domain $Target
    } elseif ($Type -eq "URL") {
        $vtData = Get-VirusTotalDataURL -URL $Target
        $alienData = Get-AlienVaultDataURL -URL $Target
        $ipqsData = Get-IPQualityScoreDataURL -URL $Target
        $urlscanData = Get-URLScanData -URL $Target
    }
    
    # Executive summary
    Write-ThreatSummary -Type $Type -VTData $vtData -AbuseData $abuseData -AlienData $alienData -IPQData $ipqsData -BlacklistData $blacklistData -URLScanData $urlscanData
    
    # Provider details
    Write-VirusTotalSection -Data $vtData -Type $Type
    
    if ($Type -eq "IP") {
        Write-AbuseIPDBSection -Data $abuseData
    }
    
    Write-AlienVaultSection -Data $alienData -Type $Type
    Write-IPQualityScoreSection -Data $ipqsData -Type $Type
    
    if ($Type -eq "URL") {
        Write-URLScanSection -Data $urlscanData
    }
    
    if ($Type -eq "IP") {
        Write-RDAPSection -Data $rdapData
        Write-BlacklistSection -Data $blacklistData
    }
    
    # Footer
    Write-Host ""
    Write-Host ("═" * 100) -ForegroundColor Cyan
    Write-Host "  Report generated by Reputation Analyzer v3.0 (IP/Domain/URL Support)" -ForegroundColor DarkGray
    Write-Host ("═" * 100) -ForegroundColor Cyan
    Write-Host ""
}

# ==================== MAIN ====================

Add-Type -AssemblyName System.Web

# Process each target
foreach ($target in $Targets) {
    $indicatorInfo = Get-IndicatorType -Indicator $target
    $type = $indicatorInfo.Type
    $cleanValue = $indicatorInfo.Value
    $displayValue = $indicatorInfo.Display
    
    Write-Host "`n[+] Detected: $type" -ForegroundColor Cyan
    if ($displayValue -ne $cleanValue) {
        Write-Host "[+] Defanged input detected. Converted: $displayValue -> $cleanValue" -ForegroundColor Yellow
    }
    
    Write-ResultsToConsole -Target $cleanValue -Type $type -DisplayValue $displayValue
    Write-Host ""
}
