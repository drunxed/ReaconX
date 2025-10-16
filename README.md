# This is your README file.
# ReaconX
A CLI TUI toolkit for port scanning and vulnerability analysis, built with Python.

# Overview
ReaconX is a terminal-based reconnaissance and vulnerability scanning toolkit that combines asynchronous network scanning with API-driven vulnerability analysis.
It provides both command-line tools and menu-driven Text User Interface (TUI) for an interactive experience.
Designed for speed, simplicity, and extensiblity, ReaconX empowers ethical hackers, students, and network analysts to perform basic assessments efficiently.

# Features
- Port scanning: Discovers open ports on target hosts using a concurrent scanner.
- Vulnerability Analysis: Performs banner grabbing, query the Vulners API, and detect common web vulnerabilties.
- Rich TUI: Terminal User Interface (tui.py) for real-time scanning progress and results.
- Asynchronous Performance: Built with asyncio and aiohttp for fast, concurrent operations.
- Flexible Targeting: Supports scanning IPs, ranges, hostnames, and URLS.

# Requirements
- Python 3.8+
- Linux(optional)
- Required Python libraries:
    - rich
    - beautifulsoup4
    - requests
    - vulners
    - nvdlib
    - aiohttp
- Install dependencies:
    pip install -r Requirements.txt

# Vulnerability Database
The vulnerability scanner uses a local signature file (`security.txt`) to identify potentially vulnerable services based on banner analysis. This file contains known service names, software identifiers, and common vulnerability patterns that help detect:

- Outdated software versions
- Known vulnerable services
- Common security indicators
- CVE patterns and references

You can customize `security.txt` to add your own signatures or remove existing ones based on your personal scanning requirements.

# Usage
Port Scanner (port_scan.py)
Scan for open ports on a target host:
# Basic port scanning
    python port_scan.py
# Scan specific target
    python port_scan.py example.com
# Custom port range
    python port_scan.py example.com 1 1024
# Scan IP addresses
    python port_scan.py 192.168.1.1

Vulnerability Scanner(vuln_scan.py)
Peform comprehensive vulnerability analysis:
# Basic vulnerability scan (default: scanme.nmap.org)
    python vuln_scan.py
# Scan specific target
    python vuln_scan.py example.com
# Scan URL for web vulnerabilities
    python vuln_scan.py https://example.com

Terminal User Interface (tui.py)
Interactive meny-driven interface for easy scanning:
    python tui.py

The TUI Menu Options:

    1. Port Scan - Scan for open ports only
    2. Vulnerability Scan - Perform security analysis only
    3. Both Scans - Run comprehensive port + vulnerability scanning
    4. Exit - Close the application





I have uploaded this for you, it is customary to have a README file within GitHub to insure that there is some documentation. Please let me know if you needed any other help. Also this is written in a language called "Markdown". I have linked it here [here](https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax)

Please let me know if you needed any help. - Md Ali
