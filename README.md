# ThreatScope

Multi-source threat intelligence analyzer for IPs, domains, and URLs.

## Description

ThreatScope is a PowerShell tool that queries multiple threat intelligence providers to analyze the reputation of IP addresses, domains, and URLs. Designed for SOC analysts and security professionals who need quick, comprehensive threat assessments.

## Features

- Analyzes IPs, domains, and URLs
- Queries 6 threat intelligence providers simultaneously
- Automatic defanging support (converts `hxxps://example[.]com` to valid format)
- Color-coded threat levels (green/yellow/red)
- Executive summary with quick threat assessment
- RDAP integration for IP registration data

## Supported Providers

- VirusTotal
- AbuseIPDB
- AlienVault OTX
- IPQualityScore
- URLScan.io
- RDAP (IP registration data)

## Requirements

- PowerShell 5.1 or higher
- API keys for desired providers

## Installation

1. Clone the repository:
```powershell
git clone https://github.com/yourusername/ThreatScope.git
cd ThreatScope
```

2. Create `APIKEYS.env` file with your API keys:
```
VT_API=your_virustotal_key
ABUSE_API=your_abuseipdb_key
ALIEN_API=your_alienvault_key
IPQ_API=your_ipqualityscore_key
URLSCAN_API=your_urlscan_key
```

## Usage

Basic syntax:
```powershell
.\ThreatScope.ps1 -Targets <indicator>
```

Examples:
```powershell
# Analyze an IP
.\ThreatScope.ps1 -Targets "8.8.8.8"

# Analyze a domain
.\ThreatScope.ps1 -Targets "example.com"

# Analyze a URL
.\ThreatScope.ps1 -Targets "https://example.com/page"

# Analyze defanged indicators
.\ThreatScope.ps1 -Targets "192.168.1[.]1"
.\ThreatScope.ps1 -Targets "hxxps://malware[.]com"

# Analyze multiple targets
.\ThreatScope.ps1 -Targets "8.8.8.8", "example.com"

# From file
Get-Content iocs.txt | .\ThreatScope.ps1
```

## API Keys

Get your free API keys from:

- VirusTotal: https://www.virustotal.com/gui/join-us
- AbuseIPDB: https://www.abuseipdb.com/register
- AlienVault OTX: https://otx.alienvault.com/
- IPQualityScore: https://www.ipqualityscore.com/create-account
- URLScan.io: https://urlscan.io/user/signup

## Threat Levels

The tool uses color-coded output to indicate threat levels:

- Green: Clean / No threats detected
- Yellow: Suspicious / Potential threat
- Red: Malicious / Confirmed threat

Thresholds are automatically calculated based on:
- VirusTotal: Percentage of vendors flagging the indicator
- AbuseIPDB: Abuse confidence score
- AlienVault: Number of threat pulses
- IPQualityScore: Fraud/risk score

## Output

The tool provides two main sections:

1. **Threat Summary**: Quick overview with color-coded status from each provider
2. **Detailed Analysis**: Comprehensive information including network details, geolocation, reputation scores, and historical data

## Defanging Support

ThreatScope automatically recognizes and converts defanged indicators:

- `[.]` becomes `.`
- `[dot]` becomes `.`
- `hxxp` becomes `http`
- `[@]` becomes `@`
- `[:]` becomes `:`

## Use Cases

- Incident response and IOC validation
- Threat hunting and correlation
- Phishing email analysis
- Network security monitoring
- Bulk IOC enrichment

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome. Please open an issue or submit a pull request.

## Disclaimer

This tool is for legitimate security research and analysis only. Users must obtain proper authorization and comply with all applicable laws and API provider terms of service.
