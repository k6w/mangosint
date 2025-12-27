> # 🥭 mangosint

## Privacy-First Modular OSINT & Infrastructure Intelligence Framework

**mangosint** is a **modular, privacy-preserving OSINT CLI framework** that aggregates, correlates, and enriches intelligence about internet-facing assets while **never exposing the user by default**.

It combines **multiple passive and active intelligence sources**, enforces **mandatory proxy usage**, normalizes all data into a shared schema, correlates infrastructure relationships, and exports clean, structured intelligence in many formats.

**Key Features:**
- **16+ Intelligence Modules**: Including 11 free modules that require no API keys
- **Comprehensive DNS Analysis**: Full record types, email security (SPF/DMARC/DKIM), reverse DNS
- **IP Intelligence**: Geolocation, ASN data, reverse DNS lookups
- **Web Security Analysis**: HTTP security headers, robots.txt parsing, favicon technology detection
- **Domain Intelligence**: WHOIS data, domain age analysis, registration information
- **Privacy-First Design**: Proxy enforcement, no direct connections, passive-first approach

## Installation

### From Source

```bash
git clone https://github.com/k6w/mangosint.git
cd mangosint
pip install -e .
```

### Platform-Specific Usage

**Linux/macOS:**
```bash
./mangosint.sh --help
```

**Windows:**
```cmd
mangosint.bat --help
```

**Or use Python directly (all platforms):**
```bash
python -m mangosint.cli --help
```

### Dependencies

```bash
pip install typer rich pydantic httpx aiofiles python-dotenv loguru tqdm
```

## Quick Start

```bash
# Initialize configuration
mangosint init

# Scan a domain
mangosint scan example.com

# Scan with specific options
mangosint scan example.com --deep --output json

# Scan multiple targets
mangosint scan targets.txt

# Check status
mangosint status network
mangosint status proxies
mangosint status modules

# List available sources
mangosint list-sources
```

**Note**: On Windows, use `mangosint.bat` instead of `mangosint`, or use `python -m mangosint.cli` on any platform.

## Configuration

On first run, mangosint will prompt you to configure proxy settings for safety.

Configuration is stored in:
- **Linux/macOS**: `~/.mangosint/config.json`
- **Windows**: `%USERPROFILE%\.mangosint\config.json`

### Quick Setup

Copy the example configuration and customize it:

**Linux/macOS:**
```bash
cp config.example.json ~/.mangosint/config.json
# Edit ~/.mangosint/config.json with your API keys and proxy settings
```

**Windows:**
```cmd
copy config.example.json %USERPROFILE%\.mangosint\config.json
# Edit %USERPROFILE%\.mangosint\config.json with your API keys and proxy settings
```

### API Keys

Many modules require API keys for external services. Configure them in your config file:

```json
{
  "api": {
    "censys_api_key": "your-censys-key",
    "shodan_api_key": "your-shodan-key",
    "virustotal_api_key": "your-vt-key",
    "alienvault_api_key": "your-otx-key",
    "certspotter_api_key": "your-certspotter-key",
    "sslmate_api_key": "your-sslmate-key",
    "urlscan_api_key": "your-urlscan-key",
    "hunter_api_key": "your-hunter-key",
    "hibp_api_key": "your-hibp-key",
    "greynoise_api_key": "your-greynoise-key"
  }
}
```

**Note**: Only configure API keys for services you plan to use. Modules without API keys will be skipped automatically.

**Note**: Censys API lookups are available to free users (1 credit per IP lookup). Domain/web property lookups may require a paid plan. Free users receive 100 credits per month.

## Features

### ✅ Implemented

- **Privacy by Default**: Proxy enforcement, DNS over proxy, IPv6 disabled
- **Modular Architecture**: 16+ intelligence modules (11 free, 5 API-based)
- **Free Intelligence Sources**: DNS records, reverse DNS, IP geolocation, security headers, robots.txt, favicon analysis, domain age
- **Comprehensive DNS Analysis**: All record types (A, AAAA, MX, TXT, NS, SOA, SRV), email security records (SPF/DMARC/DKIM)
- **IP Intelligence**: Geolocation from free services, ASN/BGP data, reverse DNS lookups
- **Web Security Analysis**: HTTP security headers with recommendations, robots.txt parsing, favicon-based technology detection
- **Domain Intelligence**: WHOIS data, domain age analysis, registration risk assessment
- **Input Processing**: Single targets, batch files, URL normalization
- **Output Formats**: JSON, TXT, CSV, HTML, SQLite
- **Export Formats**: GraphML, Mermaid
- **Status Commands**: Network, proxy, and module status
- **First-Run Safety**: Interactive proxy setup
- **Batch Scanning**: Process multiple targets
- **Async Operations**: Concurrent module execution
- **Advanced Port Scanning**: Real TCP connection attempts with banner grabbing and protocol detection
- **Correlation Engine**: Cross-source intelligence correlation
- **API Integration**: 10+ external intelligence services
- **Safety Controls**: Blacklist official services, private IP protection

### 🚧 In Development

- **Web UI**: Browser-based interface
- **Historical Tracking**: Asset change monitoring
- **Distributed Scanning**: Multi-node scanning clusters

## Available Modules

| Module | Description | Permissions | API Required | Key Attributes Provided |
|--------|-------------|-------------|--------------|-------------------------|
| **dns** | DNS resolution and comprehensive record lookup | network | No | **IPs**, DNS records, mail servers, SPF/DMARC/DKIM |
| **rdns** | Reverse DNS (PTR) record lookup | network | No | **Reverse DNS** hostnames |
| **geoip** | IP geolocation and location intelligence | network | No | **Geolocation**, country, city, ISP |
| **crtsh** | Certificate Transparency logs from crt.sh | network | No | **Certificates**, **subdomains**, issuer info |
| **whois** | Whois domain registration information | network | No | **Organization**, registration dates, registrar |
| **asn** | ASN and BGP information lookup | network | No | **ASN**, **organization**, **ISP**, **country**, **city** |
| **http** | HTTP headers and metadata analysis | network, active | No | **Technologies**, server headers, redirects |
| **security** | HTTP security headers and configuration analysis | network, active | No | Security headers, **security analysis**, recommendations |
| **robots** | Robots.txt analysis and crawler directives | network, active | No | Crawler directives, sitemaps, user agents |
| **favicon** | Favicon analysis and technology fingerprinting | network, active | No | **Technologies** via favicon hashing |
| **domainage** | Domain age and registration information | network | No | Domain age, registration info, risk assessment |
| **ports** | Advanced port scanning with protocol detection | network, active | No | **Ports**, **services**, service versions, banners |
| **alienvault** | AlienVault Open Threat Exchange intelligence | network, api | Yes | **IPs**, threat intelligence, malware indicators |
| **certspotter** | CertSpotter certificate transparency monitoring | network, api | Yes | **Certificates**, **subdomains**, certificate metadata |
| **urlscan** | URLScan.io website scanning data | network, api | Optional | **Technologies**, security headers, **certificates** |
| **hunter** | Hunter.io email discovery | network, api | Yes | **Emails**, email patterns |
| **hibp** | HaveIBeenPwned breach data | network, api | Optional | **Breaches**, compromised data |
| **greynoise** | GreyNoise IP context and scanner intelligence | network, api | Optional | **IP context**, scanner classification |
| **censys** | Censys internet-wide scanning data | network, api | Yes | **Ports**, **services**, **technologies** |
| **shodan** | Shodan internet-wide scanning data | network, api | Yes | **Ports**, **services**, **technologies**, banners |
| **virustotal** | VirusTotal domain and IP analysis | network, api | Yes | **Subdomains**, security analysis, malware detection |

## Intelligence Attributes

mangosint collects and correlates the following intelligence attributes:

### 🔍 **IP Addresses** (`ips`)
- IPv4/IPv6 addresses resolved from domains
- Detailed IP metadata when using `--deep` scanning
- **Sources**: `dns`, `crtsh`, `censys`, `shodan`, `virustotal`, `alienvault`

### 🌐 **Subdomains** (`subdomains`)
- Discovered subdomains from certificate transparency
- Subdomain enumeration from various sources
- **Sources**: `crtsh`, `certspotter`, `virustotal`, `censys`

### 🔒 **SSL Certificates** (`certificates`)
- Certificate transparency data
- Issuer information, validity dates
- Certificate fingerprints and metadata
- **Sources**: `crtsh`, `certspotter`, `censys`

### 🚪 **Open Ports** (`ports`)
- Discovered open ports on target IPs
- Port scanning results (requires `--active`)
- **Sources**: `ports`, `censys`, `shodan`

### ⚙️ **Services** (`services`)
- Detected services running on ports
- Service banners and version information
- **Sources**: `censys`, `shodan`, `ports`

### 🏗️ **Technologies** (`technologies`)
- Web technologies, frameworks, and libraries
- Server software and middleware detection
- **Sources**: `http`, `censys`, `shodan`

### 🏢 **Organization & ASN** (`asn`, `organization`)
- Autonomous System Numbers
- Organization and ISP information
- Geographic location data (country, city)
- **Sources**: `asn`, `whois`, `geoip` (with `--deep`)

### 📧 **DNS Records** (`dns_records`)
- Comprehensive DNS record types (A, AAAA, MX, TXT, NS, SOA, SRV)
- Mail server configurations and email security records
- **Sources**: `dns`

### 🔐 **Email Security** (`spf_records`, `dmarc_records`, `dkim_records`)
- SPF, DMARC, and DKIM email security configurations
- Email authentication and anti-spoofing analysis
- **Sources**: `dns`

### 🔄 **Reverse DNS** (`reverse_dns`)
- PTR record lookups for IP-to-hostname resolution
- Hostname discovery from IP addresses
- **Sources**: `rdns`

### 🌍 **Geolocation** (`geolocation`)
- IP address geographic location data
- Country, city, ISP, and network information
- **Sources**: `geoip`, `asn`

### 🛡️ **Security Analysis** (`security_analysis`)
- HTTP security header analysis and recommendations
- Security configuration scoring and risk assessment
- **Sources**: `security`

### 🤖 **Crawler Directives** (`robots_txt`)
- Robots.txt parsing and analysis
- Crawler permissions and sitemap discovery
- **Sources**: `robots`

### 🎨 **Favicon Analysis** (`favicon`)
- Technology fingerprinting via favicon hashing
- Framework and CMS detection through favicon analysis
- **Sources**: `favicon`

### 📅 **Domain Information** (`domain_info`)
- Domain registration dates and age analysis
- Registrar information and risk assessment
- **Sources**: `domainage`

### 🔓 **Security Breaches** (`breaches`)
- Data breaches affecting the target domain
- Breach details, dates, and compromised data types
- **Sources**: `hibp`

### 🛡️ **Security Headers** (`security_headers`)
- HTTP security headers detected on websites
- Security configuration analysis
- **Sources**: `urlscan`

### 📡 **Service Banners** (`service_banners`)
- Raw service banners and protocol responses
- Detailed service identification and version information
- **Sources**: `ports`

### 🎯 **IP Context** (`ip_context`)
- IP address classification (benign/malicious/scanner)
- GreyNoise intelligence and scanner identification
- **Sources**: `greynoise`

### 🏷️ **Categories & Tags** (`categories`, `threat_tags`)
- Content categories and threat intelligence tags
- Service classification and security indicators
- **Sources**: `virustotal`, `alienvault`

### 📊 **Reputation Scores** (`reputation_score`)
- Domain/IP reputation scores from security services
- Malware and threat analysis ratings
- **Sources**: `virustotal`

### 📈 **Threat Intelligence** (`threat_pulses`, `validation`)
- AlienVault threat pulses and validation data
- Community threat intelligence
- **Sources**: `alienvault`

## Module Intelligence Matrix

| Attribute | dns | rdns | geoip | crtsh | whois | asn | http | security | robots | favicon | domainage | ports | alienvault | certspotter | urlscan | hunter | hibp | greynoise | censys | shodan | virustotal |
|-----------|-----|------|-------|-------|-------|-----|------|----------|--------|---------|-----------|-------|------------|------------|-------------|---------|--------|------|--------|--------|------------|
| **IPs** | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| **Subdomains** | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ |
| **Certificates** | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **Ports** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| **Services** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| **Technologies** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| **ASN/Org** | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Location** | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **DNS Records** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Email Security** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Reverse DNS** | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Geolocation** | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Security Analysis** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Robots.txt** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Favicon** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Domain Info** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Emails** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Breaches** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Security Headers** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Service Banners** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **IP Context** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| **Categories/Tags** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Reputation** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Threat Intel** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

## Intelligence Gathering Workflow

When you run a scan, mangosint follows this process:

1. **Input Processing**: Normalize targets (domains, IPs, URLs)
2. **Module Execution**: Run enabled intelligence modules concurrently
3. **Data Aggregation**: Combine results from all sources
4. **Correlation**: Link related infrastructure (IP → domains, certificates → subdomains)
5. **Enrichment**: Add detailed metadata (ASN info, geolocation)
6. **Output**: Format results in your chosen output format

### Example: Complete Domain Intelligence

```bash
mangosint scan example.com --deep --output json
```

**What you get:**
- **DNS Resolution**: All IP addresses for the domain
- **Comprehensive DNS Records**: A, AAAA, MX, TXT, NS, SOA, SRV records
- **Email Security**: SPF, DMARC, DKIM configurations and analysis
- **Reverse DNS**: PTR record lookups for IP-to-hostname resolution
- **IP Geolocation**: Geographic location, ISP, and network information
- **Certificate Intelligence**: SSL certificates from transparency logs
- **Subdomain Discovery**: Related subdomains from certificates
- **ASN Intelligence**: BGP routing, organization, and location data
- **Whois Data**: Domain registration information and age analysis
- **Security Headers**: HTTP security analysis with recommendations
- **Web Crawler Analysis**: Robots.txt parsing and sitemap discovery
- **Technology Fingerprinting**: Favicon-based framework and CMS detection
- **Advanced Port Scanning**: Real TCP port scanning with protocol detection and service banners
- **Technology Detection**: Web frameworks, server software, and middleware
- **Threat Intelligence**: VirusTotal analysis, AlienVault pulses, GreyNoise context
- **Security Analysis**: HTTP security headers, breach data, reputation scores

### Privacy & Safety

- **Proxy Enforcement**: All network requests go through configured proxies
- **Passive-First**: Default behavior uses only passive intelligence sources
- **Rate Limiting**: Built-in delays to avoid detection
- **No Direct Connections**: Never connects directly to target infrastructure
- **Configurable Anonymity**: Tor support, custom proxy chains, VPN integration

## Usage Examples

### Basic Scanning
```bash
# Single domain - all passive intelligence
mangosint scan example.com

# Multiple targets from file
mangosint scan targets.txt

# Active scanning with port detection (noisier)
mangosint scan example.com --active
```

### Getting Specific Attributes

```bash
# IP addresses only
mangosint scan example.com --enable dns --output json

# Certificates and subdomains
mangosint scan example.com --enable crtsh,certspotter --output json

# Detailed IP intelligence (ASN, location, organization)
mangosint scan example.com --deep --enable dns,asn,whois --output json

# Ports and services with protocol detection (requires --active)
mangosint scan example.com --active --enable ports --output json

# Web technologies and server info
mangosint scan example.com --enable http,censys,shodan --output json

# Threat intelligence and security analysis
mangosint scan example.com --enable virustotal,alienvault,greynoise --output json

# Email discovery and breach data
mangosint scan example.com --enable hunter,hibp --output json

# Complete intelligence profile with all sources
mangosint scan example.com --deep --output json
```

### Output Formats
```bash
# JSON (default, most detailed)
mangosint scan example.com --output json

# Human-readable text
mangosint scan example.com --output txt

# CSV for spreadsheet analysis
mangosint scan example.com --output csv

# HTML report
mangosint scan example.com --output html

# SQLite database
mangosint scan example.com --output sqlite
```

### Export Formats
```bash
# GraphML for network visualization
mangosint scan example.com --export graphml

# Mermaid diagrams
mangosint scan example.com --export mermaid
```

### Source Control
```bash
# Enable specific sources
mangosint scan example.com --enable dns,crtsh,censys

# Disable noisy sources
mangosint scan example.com --disable shodan

# Passive-only (exclude active modules)
mangosint scan example.com --passive-only
```

### Network Modes
```bash
# Offline mode (DNS only, no network)
mangosint scan example.com --network offline

# Passive mode (default - safe, no active probing)
mangosint scan example.com --network passive

# Active mode (port scanning, service detection)
mangosint scan example.com --network active
```

## Troubleshooting

### Missing Attributes in Results

**Problem**: Some attributes (IPs, subdomains, etc.) don't appear in scan results.

**Solutions**:
```bash
# Enable modules that provide missing attributes
mangosint scan example.com --enable dns,crtsh,asn

# Use deep scanning for detailed IP metadata
mangosint scan example.com --deep --enable dns,asn,whois

# Run all modules for complete intelligence
mangosint scan example.com  # No --enable flag = all modules
```

### API-Related Issues

**Problem**: Modules requiring API keys are skipped.

**Solutions**:
```bash
# Check which modules need API keys
mangosint list-sources

# Configure API keys in ~/.mangosint/config.json
# See Configuration section above

# Test specific API-dependent modules
mangosint scan example.com --enable censys --output json
```

### Proxy Configuration

**Problem**: "No proxy configured" or connection failures.

**Solutions**:
```bash
# Re-run first-time setup
mangosint init

# Check proxy status
mangosint status proxies

# Configure custom proxy
# Edit ~/.mangosint/config.json
```

### Empty Results

**Problem**: Scan returns no intelligence data.

**Possible causes**:
- Network connectivity issues
- Overly restrictive proxy configuration
- Target has no public intelligence available
- All API-dependent modules are disabled

**Debug**:
```bash
# Check network status
mangosint status network

# Test with minimal modules
mangosint scan example.com --enable dns --network offline

# Check proxy connectivity
mangosint status proxies
```
