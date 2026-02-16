# ThreatScope

[![Latest Release](https://img.shields.io/github/v/release/alex-milla/ThreatScope)](https://github.com/alex-milla/ThreatScope/releases/latest)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Multi-source threat intelligence analyzer for IPs, domains, and URLs.

## Description

ThreatScope is a PowerShell tool that queries multiple threat intelligence providers to analyze the reputation of IP addresses, domains, and URLs. Designed for SOC analysts and security professionals who need quick, comprehensive threat assessments.

## Features

- **Multi-Indicator Support**: Analyzes IPs, domains, and URLs
- **6 Threat Intelligence Providers**: Queries VirusTotal, AbuseIPDB, AlienVault OTX, IPQualityScore, URLScan.io, and RDAP simultaneously
- **Automatic Defanging**: Converts defanged indicators (e.g., `hxxps://example[.]com`) to valid format automatically
- **Interactive Mode**: User-friendly menu system for easy analysis
- **Batch Processing**: Analyze multiple indicators from CSV or TXT files
- **Smart Rate Limiting**: Auto, Strict, and None modes to respect free API tier limits
- **Color-Coded Results**: Visual threat levels (green/yellow/red) for quick assessment
- **Intelligent Threat Scoring**: Combines data from multiple sources into a unified threat score (0-100)
- **Malicious Indicator Reports**: Automatically generates detailed TXT reports for malicious findings
- **Export Capabilities**: Save analysis results to CSV or JSON
- **RDAP Integration**: IP registration and network ownership data
- **Progress Tracking**: Real-time status updates during batch analysis

## Supported Providers

- **VirusTotal**: Community scores and vendor detections
- **AbuseIPDB**: Abuse confidence scoring and reporting (IP only)
- **AlienVault OTX**: Threat pulses and IOC correlation
- **IPQualityScore**: Fraud detection, proxy/VPN/TOR identification
- **URLScan.io**: URL scanning and analysis (URL only)
- **RDAP**: IP registration data and contacts (IP only)

## Requirements

- PowerShell 5.1 or higher
- API keys for desired providers (free tier available for all)

## Installation

1. Clone the repository:
```powershell
git clone https://github.com/alex-milla/ThreatScope.git
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

3. Run the script:
```powershell
.\ThreatScope.ps1
```

## Usage

### Interactive Mode (Recommended)

Simply run the script without parameters for an interactive menu:

```powershell
.\ThreatScope.ps1
```

You'll be prompted to choose:
1. Analyze single indicator (IP, Domain, or URL)
2. Batch analysis from file (CSV or TXT)
3. Exit

### Single Indicator Analysis

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
.\ThreatScope.ps1 -Targets "8.8.8.8", "example.com", "https://test.com"
```

### Batch Analysis from File

```powershell
# From TXT file
.\ThreatScope.ps1 -InputFile "iocs.txt"

# From CSV file with output
.\ThreatScope.ps1 -InputFile "indicators.csv" -OutputFile "results.csv"

# With strict rate limiting
.\ThreatScope.ps1 -InputFile "iocs.txt" -RateLimitMode Strict
```

### Rate Limiting Modes

- **Auto** (default): Automatic rate limiting based on free API tier limits
- **Strict**: Conservative mode with extra delays between requests
- **None**: No rate limiting (for paid API tiers)

```powershell
.\ThreatScope.ps1 -Targets "8.8.8.8" -RateLimitMode Strict
```

### File Input Formats

**TXT format** (one indicator per line):
```
8.8.8.8
example.com
https://test.com
192.168.1[.]100
hxxps://malicious[.]site
```

**CSV format** (automatic column detection):
```csv
Indicator
8.8.8.8
example.com
https://test.com
```

Supported column names: `IP`, `Domain`, `URL`, `Indicator`, `IOC`, `Address`, `Host`, `Target`

## Output Examples

### Console Output

The tool provides color-coded output with:

- **Executive Summary**: Quick overview from all providers
- **Detailed Analysis**: Comprehensive information per provider
- **Threat Score**: Calculated score from 0-100
- **Verdict**: CLEAN / SUSPICIOUS / MALICIOUS

### Malicious Indicators Report

When malicious indicators are detected, ThreatScope automatically generates a detailed report:

**Filename**: `MALICIOUS_INDICATORS_YYYYMMDD_HHMMSS.txt`

Contents include:
- Complete indicator details
- Threat scores from all providers
- Geolocation and ISP information
- Recommended security actions

### CSV Export

All batch analysis results can be exported to CSV with columns:
- Indicator, Type, Verdict, ThreatScore
- VT_Detections, VT_Status
- Abuse_Score, Abuse_Reports, Abuse_Status
- Alien_Pulses, Alien_Status
- IPQ_Score, IPQ_Status
- Blacklisted, Country, ISP

## API Keys

Get your free API keys from:

- **VirusTotal**: https://www.virustotal.com/gui/join-us
- **AbuseIPDB**: https://www.abuseipdb.com/register
- **AlienVault OTX**: https://otx.alienvault.com/
- **IPQualityScore**: https://www.ipqualityscore.com/create-account
- **URLScan.io**: https://urlscan.io/user/signup

## Rate Limits (Free API Tiers)

| Provider | Requests per Minute | Requests per Day | Requests per Month |
|----------|---------------------|------------------|-------------------|
| VirusTotal | 4 | 500 | 15,500 |
| AbuseIPDB | - | 1,000 | 30,000 |
| AlienVault OTX | Unlimited | Unlimited | Unlimited |
| IPQualityScore | - | - | 5,000 |
| URLScan.io | - | 50 | - |

ThreatScope automatically manages these limits when using Auto or Strict rate limiting modes.

## Threat Scoring

The tool uses an intelligent algorithm to calculate threat scores:

- **VirusTotal**: 40% weight based on vendor detections
- **AbuseIPDB**: 30% weight based on abuse confidence score
- **AlienVault OTX**: 20% weight based on threat pulse count
- **IPQualityScore**: 10% weight based on fraud/risk score

**Verdict Thresholds**:
- **0-39**: CLEAN
- **40-69**: SUSPICIOUS
- **70-100**: MALICIOUS

## Defanging Support

ThreatScope automatically recognizes and converts defanged indicators:

| Defanged Format | Converts To |
|-----------------|-------------|
| `[.]` or `[dot]` | `.` |
| `hxxp` or `hXXp` | `http` |
| `[@]` | `@` |
| `[:]` | `:` |

Example: `hxxps://malware[.]com/payload` → `https://malware.com/payload`

## Use Cases

- **Incident Response**: Quick IOC validation and triage
- **Threat Hunting**: Correlation across multiple threat intelligence sources
- **Email Security**: Analyze suspicious domains and URLs from phishing emails
- **Network Security Monitoring**: Investigate unusual outbound connections
- **Bulk IOC Enrichment**: Process large lists of indicators from threat feeds
- **Security Operations**: Daily SOC workflows and alert validation

## Project Structure

```
ThreatScope/
├── ThreatScope.ps1          # Main PowerShell script
├── README.md                # This file
├── APIKEYS.env              # Your API keys (not in repo)
├── APIKEYS.env.example      # API keys template
├── LICENSE                  # MIT License
├── .gitignore              # Git ignore rules
└── CHANGELOG.md            # Version history
```

## Security Considerations

- All API communications use HTTPS encryption
- No data is stored or transmitted to third parties
- API keys are stored locally in `APIKEYS.env`
- Automatic `.gitignore` prevents accidental key commits
- Respects API provider rate limits and terms of service

## Troubleshooting

### API Key Errors
- Ensure `APIKEYS.env` exists in the same directory as the script
- Verify API keys are valid and active
- Check if you've exceeded rate limits

### Rate Limit Issues
- Use `-RateLimitMode Strict` for more conservative API usage
- Monitor rate limit status displayed after batch analysis
- Consider upgrading to paid API tiers for higher limits

### File Import Errors
- Ensure file exists and path is correct
- For CSV files, use supported column names
- Remove empty lines and comments (lines starting with `#`)

## Contributing

Contributions are welcome! Please feel free to:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Roadmap

Future enhancements being considered:

- GreyNoise integration
- Shodan API support
- HTML report generation with charts
- Passive DNS lookups
- Historical analysis tracking
- MISP integration
- Automated IOC enrichment pipelines
- GUI version with dashboards

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for legitimate security research and analysis only. Users must:

- Obtain proper authorization before analyzing systems/networks
- Comply with API provider terms of service
- Adhere to applicable laws and regulations
- Respect rate limits and fair use policies

The authors assume no liability for misuse of this tool.

## Acknowledgments

- **VirusTotal**, **AbuseIPDB**, **AlienVault OTX**, **IPQualityScore**, and **URLScan.io** for their excellent threat intelligence APIs
- The cybersecurity community for making threat intelligence sharing possible
- All contributors and users who help improve this tool

## Author

**Alex Milla**
- Websites: [alexmilla.dev](https://alexmilla.dev)

---

**Made with ❤️ by security professionals, for security professionals**

If you find ThreatScope useful, please consider giving it a star ⭐
