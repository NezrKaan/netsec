# NetSec Audit Tool - Network Security Scanner

**Created by: Nezir Kaan Bilgehan**

A comprehensive network security audit tool designed for penetration testing and security assessment. This tool performs systematic network reconnaissance, vulnerability detection, and security analysis across multiple phases.

## Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/nezrkaan/netsec.git
cd netsec
```

### Step 2: Install System Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install traceroute python3 python3-pip

# CentOS/RHEL/Fedora
sudo yum install traceroute python3 python3-pip
# or for newer versions:
sudo dnf install traceroute python3 python3-pip

# Arch Linux
sudo pacman -S traceroute python python-pip
```

### Step 3: Install Python Dependencies

**Option A: System Packages (Recommended)**
```bash
# Ubuntu/Debian
sudo apt install python3-dnspython python3-colorama python3-requests python3-netifaces

# This method avoids virtual environment issues and integrates better with system Python
```

**Option B: Using pip**
```bash
# If you encounter "externally-managed-environment" error, use:
pip install -r requirements.txt --break-system-packages

# Or create a virtual environment:
python3 -m venv netsec-env
source netsec-env/bin/activate
pip install -r requirements.txt
```

### Step 4: Make Executable and Test
```bash
chmod +x netsec-audit.py
python3 netsec-audit.py --help
```

### Step 5: Quick Test
```bash
# Test the tool with a simple scan
python3 netsec-audit.py --target google.com --ports 80,443
```

### Troubleshooting Installation

**If you see DNS enumeration warnings:**
```bash
sudo apt install python3-dnspython
```

**If traceroute fails:**
```bash
sudo apt install traceroute
```

**For "externally-managed-environment" error:**
Use system packages (Option A) or create a virtual environment as shown above.

## Quick Start

After installation, you can immediately start using the tool:

```bash
# Basic scan
python3 netsec.py --target example.com

# Comprehensive scan
python3 netsec.py --target 192.168.1.1 --comprehensive

# Generate HTML report
python3 netsec.py --target example.com --export report.html --format html
```

## How It Works

### Program Architecture

The NetSec Audit Tool operates through a multi-phase scanning methodology that systematically analyzes network targets. The program is built using Python and implements various network security assessment techniques.

### Scanning Phases

**Phase 1: Reconnaissance**
- Gathers system information about the local machine
- Enumerates network interfaces and configurations
- Establishes baseline information for the audit

**Phase 2: DNS Enumeration**
- Performs DNS lookups for A, MX, NS, and TXT records
- Resolves domain names to IP addresses
- In comprehensive mode, attempts subdomain enumeration

**Phase 3: Port Scanning**
- Uses multi-threaded TCP SYN scanning for port discovery
- Implements configurable timeout and concurrency settings
- Supports both common port lists and full port range scanning
- Can perform UDP scanning for specific services

**Phase 4: OS Detection**
- Analyzes TTL values from ping responses
- Cross-references open ports with known OS fingerprints
- Provides confidence scoring for OS identification

**Phase 5: Service Enumeration**
- Performs banner grabbing on discovered open ports
- Analyzes HTTP/HTTPS services for server information
- Extracts SSL certificate details and validates security
- Identifies web technologies and security headers

**Phase 6: Firewall Detection**
- Tests for port filtering behaviors
- Analyzes response patterns to identify firewall presence
- Evaluates network access control implementations

**Phase 7: Network Tracing**
- Performs traceroute analysis to map network path
- Measures response times and network latency
- Identifies network infrastructure components

**Phase 8: Vulnerability Assessment**
- Analyzes discovered services for known security issues
- Identifies insecure protocols and configurations
- Evaluates attack surface and exposure risks
- Calculates numerical risk scores based on findings

**Phase 9: Advanced Scanning (Optional)**
- Integrates with Nmap for advanced vulnerability detection
- Performs script-based security assessments
- Conducts comprehensive service version analysis

**Phase 10: Recommendations Generation**
- Provides specific security recommendations based on findings
- Prioritizes remediation efforts by risk level
- Offers actionable steps for security improvements

### Technical Implementation

**Multi-threading**
The program uses Python's ThreadPoolExecutor to perform concurrent port scanning operations. This allows for efficient scanning of large port ranges while maintaining system stability.

**Socket Programming**
Direct socket connections are established for port scanning and service detection. The program implements proper timeout handling and connection management.

**Protocol Analysis**
Service identification is performed through banner grabbing and protocol-specific probes. HTTP services receive specialized analysis for web security assessment.

**Risk Calculation**
The program implements a scoring algorithm that evaluates multiple security factors including open ports, insecure services, missing security controls, and identified vulnerabilities.

## Installation

### Prerequisites
- Python 3.7 or higher
- Administrative privileges for some scanning functions
- Network connectivity to target systems
- Git for cloning the repository

### Repository Structure
After cloning, your directory will contain:
```
netsec-audit-tool/
├── netsec-audit.py          # Main application
├── requirements.txt         # Python dependencies
├── README.md               # This documentation
└── LICENSE                 # MIT License
```

### System Dependencies
```bash
# Ubuntu/Debian
sudo apt install traceroute python3-pip

# Install Python packages
sudo apt install python3-dnspython python3-colorama python3-requests python3-netifaces
```

### Alternative Installation
```bash
# If you prefer using pip directly
pip install -r requirements.txt

# Note: On newer systems, you may need to use virtual environments
# or the --break-system-packages flag to avoid pip restrictions
```

## Usage

### Basic Scanning
```bash
python3 netsec-audit.py --target example.com
```

### Port-Specific Scanning
```bash
python3 netsec-audit.py --target 192.168.1.1 --ports 22,80,443,8080
```

### Comprehensive Assessment
```bash
python3 netsec-audit.py --target example.com --comprehensive
```

### Maximum Security Audit
```bash
python3 netsec-audit.py --target example.com --all
```

### Report Generation
```bash
python3 netsec-audit.py --target example.com --export security_report.html --format html
```

## Command Line Options

```
--target, -t          Target IP address or hostname (required)
--ports, -p           Comma-separated list of specific ports to scan
--comprehensive, -c   Perform extended scanning across all phases
--deep-scan          Enable Nmap integration for vulnerability detection
--all                Execute maximum comprehensive scan (all techniques)
--export, -e         Export results to specified file
--format, -f         Output format: json, html, txt
--timeout            Set port scanning timeout in seconds
--all-ports          Scan complete port range (1-65535)
```

## Command Line Options

```
--target, -t          Target IP address or hostname (required)
--ports, -p           Comma-separated list of specific ports to scan
--comprehensive, -c   Perform extended scanning across all phases
--deep-scan          Enable Nmap integration for vulnerability detection
--all                Execute maximum comprehensive scan (all techniques)
--export, -e         Export results to specified file
--format, -f         Output format: json, html, txt
--timeout            Set port scanning timeout in seconds
--all-ports          Scan complete port range (1-65535)
```

## Output and Reporting

### Console Output
The program provides real-time feedback during scanning operations, displaying discovered services, identified vulnerabilities, and security findings as they are detected.

### Risk Assessment
Results include a numerical risk score (0-100) calculated based on:
- Number and type of open ports
- Presence of insecure services
- Missing security controls
- Identified vulnerabilities
- Attack surface exposure

### Export Formats
- **JSON**: Machine-readable format for integration with other tools
- **HTML**: Professional report format with styled presentation
- **TXT**: Plain text format for documentation and archival

## Security Considerations

### Ethical Use
This tool is intended for authorized security testing only. Users must ensure they have proper permission before scanning any network infrastructure.

### Network Impact
The scanning operations generate network traffic that may be detected by security monitoring systems. Consider the impact on network performance and security alerting.

### Legal Compliance
Network scanning may be subject to legal restrictions in various jurisdictions. Users are responsible for ensuring compliance with applicable laws and regulations.

## Technical Requirements

### Dependencies
- colorama: Terminal color output
- requests: HTTP/HTTPS communication
- netifaces: Network interface enumeration
- python-nmap: Advanced scanning capabilities
- dnspython: DNS resolution and enumeration

### Performance Characteristics
- Multi-threaded scanning supports up to 100 concurrent connections
- Memory usage scales with port range and target count
- Scanning time varies based on network latency and target responsiveness

## Advanced Features

### Nmap Integration
When python-nmap is available, the tool can leverage Nmap's advanced scanning capabilities for vulnerability detection and service enumeration.

### Subdomain Enumeration
In maximum scan mode, the program attempts to discover subdomains using common naming patterns.

### Database Detection
The tool identifies common database services (MySQL, PostgreSQL, MongoDB, Redis) and evaluates their security exposure.

### Certificate Analysis
SSL/TLS certificates are extracted and analyzed for validity, encryption strength, and security configuration.

## Contributing

Contributions to improve the tool's capabilities or documentation are welcome. Please ensure any modifications maintain the tool's focus on security education and ethical use.

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Author

Nezir Kaan Bilgehan

## Disclaimer

This tool is provided for educational and authorized testing purposes only. Users assume full responsibility for compliance with applicable laws and regulations.
