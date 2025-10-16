
# Vulnerability Analyzer Script

# Import libraries
import socket
import requests
from bs4 import BeautifulSoup
import urllib.parse
import re
import sys
import os
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Optional, Tuple
import json
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

# Class for Vulnerbaility Scanner
class VulnerabilityScanner:
    def __init__(self, target: str, vuln_file: str = 'security.txt'):
        self.target = target
        self.vuln_file = vuln_file
        self.console = Console()
        self.scan_start_time: Optional[float] = None
        self.scan_end_time: Optional[float] = None

        # Results storage
        self.network_results: Dict = {}
        self.web_results: Dict = {}
        self.open_ports: List[int] = []
        self.port_banners: List[Tuple[int, str]] = []
        self.network_vulns: List[str] = []
        self.web_vulns: List[str] = []

        # Initialize sub-scanners
        self.net_scanner = None
        self.web_scanner = None

    # Main scanning method that performs both network and web vulnerability scans
    def scan(self):
        self.scan_start_time = time.time()
        self.console.print(f"\n[bold purple]Starting vulnerability scan on {self.target}[/bold purple]")

        # Network scan
        self._scan_network()

        # Web scan (if target is URL)
        if self.target.startswith('http'):
            self._scan_web()

        self.scan_end_time = time.time()

    # Perform network vulnerability scanning
    def _scan_network(self):
        self.console.print("\n[bold yellow]Performing network scan...[/bold yellow]")

        # Initialize network scanner
        self.net_scanner = NetworkScanner(self.target)
        self.port_banners = self.net_scanner.scan_ports()

        # Store results
        self.open_ports = self.net_scanner.open_ports
        self.network_results = {
            'open_ports': self.open_ports,
            'port_banners': self.port_banners
        }

        # Check for network vulnerabilities
        self.network_vulns = check_vulns([b for _, b in self.port_banners], self.vuln_file)

        
    # Perform web vulnerability scanning
    def _scan_web(self):
        """Perform web vulnerability scanning"""
        self.console.print("\n[bold yellow]Performing web scan...[/bold yellow]")

        # Initialize web scanner
        self.web_scanner = WebScanner(self.target)
        urls = self.web_scanner.crawl(self.target)

        if urls:
            self.console.print(f"[green]Crawled {len(urls)} URLs[/green]")
            self.web_results['crawled_urls'] = urls

            # Check for web vulnerabilities
            web_vulns = []
            with Progress() as progress:
                task = progress.add_task("Scanning for web vulnerabilities...", total=len(urls) * 2)

                with ThreadPoolExecutor(max_workers=5) as executor:
                    # Submit XSS checks
                    xss_futures = [executor.submit(check_xss, u) for u in urls]
                    # Submit SQLi checks
                    sqli_futures = [executor.submit(check_sqli, u) for u in urls]

                    # Combine all futures
                    all_futures = xss_futures + sqli_futures

                    # Collect results with progress updates
                    for future in all_futures:
                        result = future.result()
                        if result:
                            web_vulns.append(result)
                        progress.update(task, advance=1)

            self.web_vulns = web_vulns
            self.web_results['vulnerabilities'] = web_vulns
        else:
            self.console.print("[red]Could not crawl any URLs[/red]")
            self.web_results['crawled_urls'] = []
            self.web_results['vulnerabilities'] = []

    # Display scan results
    def display_results(self):
        if not self.scan_start_time:
            self.console.print("[red]No results available. Run scan() first.[/red]")
            return

        # Calculate scan duration
        scan_duration = self.scan_end_time - self.scan_start_time if self.scan_end_time else 0

        # Summary display
        summary_text = f"""
[bold]Vulnerability Scan Summary:[/bold]
Target: [cyan]{self.target}[/cyan]
Scan Duration: [cyan]{scan_duration:.2f} seconds[/cyan]
Network Vulnerabilities: [yellow]{len(self.network_vulns)}[/yellow]
Web Vulnerabilities: [yellow]{len(self.web_vulns)}[/yellow]
Total Vulnerabilities: [yellow]{len(self.network_vulns) + len(self.web_vulns)}[/yellow]
        """
        self.console.print(Panel(summary_text.strip(), title="[bold blue]Vulnerability Scan Results[/bold blue]"))

        # Display open ports table (similar to port_scanner format)
        if self.open_ports:
            table = Table(title="Open Ports Discovered")
            table.add_column("Port", style="cyan", justify="right")
            table.add_column("Banner Preview", style="yellow", max_width=50)

            for port, banner in self.port_banners:
                banner_preview = banner[:50] + ("..." if len(banner) > 50 else "")
                table.add_row(str(port), banner_preview)

            self.console.print("\n", table)

        # Display network vulnerabilities
        if self.network_vulns:
            vuln_table = Table(title="Network Vulnerabilities")
            vuln_table.add_column("Vulnerability", style="red", max_width=80)

            for vuln in self.network_vulns:
                vuln_table.add_row(vuln)

            self.console.print("\n", vuln_table)

        # Display web vulnerabilities
        if self.web_vulns:
            vuln_table = Table(title="Web Vulnerabilities")
            vuln_table.add_column("Vulnerability", style="red", max_width=80)

            for vuln in self.web_vulns:
                vuln_table.add_row(vuln)

            self.console.print("\n", vuln_table)

        # No vulnerabilities found message
        if not self.network_vulns and not self.web_vulns:
            self.console.print("\n[green]No vulnerabilities found![/green]")

        self.console.print(f"\n[green]Vulnerability scan completed in {scan_duration:.2f} seconds.[/green]\n")

# Class for scanning network ports
class NetworkScanner:
    def __init__(self, target, port_range=(1, 1025)):
        # Initialize the scanner with target IP/hostname and port range
        # Extract hostname if target is a URL
        if target.startswith('http://') or target.startswith('https://'):
            parsed = urllib.parse.urlparse(target)
            hostname = parsed.hostname
        else:
            hostname = target

        try:
            # Check if hostname is None or empty
            if not hostname:
                print("Error: Invalid target - no hostname found")
                sys.exit(1)

            # Check if it's already an IP address
            import ipaddress
            try:
                ipaddress.ip_address(hostname)
                self.target = hostname
            except ValueError:
                # Not an IP address, resolve hostname
                self.target = socket.gethostbyname(hostname)
        except socket.gaierror:
            print(f"Error: Could not resolve hostname '{hostname}'")
            sys.exit(1)
        self.port_range = list(range(port_range[0], port_range[1] + 1)) # Includes end port
        self.open_ports = []
        self.banners = []

    def scan_ports(self):
        # Function to scan ports in the specified range
        def check_port(port):
            # Inner function to check if a port is open and grab banner
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    # Try to receive banner with improved grabbing logic
                    banner = _grab_banner(sock, port, self.target)
                    sock.close()
                    return (port, banner)
                else:
                    sock.close()
                    return None
            except Exception as e:
                return None

        # Grab banner for different services
        def _grab_banner(sock, port, target):
            banner = ""
            try:
                sock.settimeout(5.0)

                # Special handling for HTTP/HTTPS ports
                if port in [80, 443]:
                    try:
                        request = f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode()
                        sock.send(request)
                        response = sock.recv(1024).decode('utf-8', errors='ignore')
                        # Extract server header from HTTP response
                        lines = response.split('\n')
                        for line in lines:
                            if line.lower().startswith('server:'):
                                banner = line.strip()
                                break
                        if not banner:
                            banner = response.split('\n')[0] if response else "HTTP Server"
                    except:
                        banner = "HTTP Server"
                else:
                    # For other ports, try to get banner
                    try:
                        banner_data = sock.recv(1024)
                        banner = banner_data.decode('utf-8', errors='ignore').strip()
                    except:
                        banner = ""

                # If no banner received, provide default based on port
                if not banner:
                    common_ports = {
                        21: "FTP Server", 22: "SSH Server", 23: "Telnet Server",
                        25: "SMTP Server", 53: "DNS Server", 110: "POP3 Server",
                        143: "IMAP Server", 443: "HTTPS Server", 993: "IMAPS Server",
                        995: "POP3S Server"
                    }
                    banner = common_ports.get(port, f"Port {port} Open")

            except Exception as e:
                banner = f"Port {port} Open"

            return banner

        # Initialize Rich console and progress
        console = Console()
        total_ports = len(self.port_range)
        results = []

        console.print(f"\n[bold yellow]Scanning {total_ports} ports...[/bold yellow]")
        with Progress() as progress:
            task = progress.add_task("Scanning ports...", total=total_ports)
            # Use thread pool to scan ports concurrently
            with ThreadPoolExecutor(max_workers=100) as executor:
                future_to_port = {executor.submit(check_port, port): port for port in self.port_range}
                for future in future_to_port:
                    result = future.result()
                    if result is not None:
                        results.append(result)
                    progress.update(task, advance=1)

        self.open_ports = [p for p, b in results]
        self.banners = [b for p, b in results]
        # Return list of tuples (port, banner)
        return results
    
# Class for scanning websites by crawling
class WebScanner:
    def __init__(self, target_url, max_depth=3):
        # Initialize with target URL and maximum crawl depth
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited = set()

    # Define crawl
    def crawl(self, url, depth=0):
        # Recursive function to crawl URLs up to max_depth
        if depth > self.max_depth or url in self.visited:
            return []
        self.visited.add(url)
        links = []
        try:
            # Fetch the page
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            # Find all links within the same domain
            links = []
            for a in soup.find_all('a', href=True):
                try:
                    # Use BeautifulSoup's Tag type checking
                    from bs4 import Tag
                    if isinstance(a, Tag):
                        href = a.get('href')
                        if href and isinstance(href, str) and href.strip():
                            full_url = urllib.parse.urljoin(url, href)
                            if urllib.parse.urlparse(full_url).netloc == urllib.parse.urlparse(self.target_url).netloc:
                                links.append(full_url)
                except (KeyError, TypeError, AttributeError):
                    continue
            for link in links:
                # Recursively crawl sub-links
                links.extend(self.crawl(link, depth + 1))
            return links
        except Exception as e:
            return []

# Function to check for vulnerabilities in banners and known services
def check_vulns(banners, vuln_file='security.txt'):
    # List to hold found vulnerabilities
    vulns = []
    # Load vulnerability signatures from file
    try:
        with open(vuln_file, 'r') as f:
            vuln_list = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        vuln_list = []
        print(f"Warning: {vuln_file} not found, skipping banner checks.")
    # Check banners against vulnerability signatures
    for banner in banners:
        for vuln in vuln_list:
            if vuln in banner:
                vulns.append(f"Vulnerable: {banner} (matches {vuln})")

    # Query Vulners API for known CVEs for common services
    for service in ['apache', 'mysql']:
        api_url = f"https://vulners.com/api/v3/search/lucene?query={service}"
        try:
            response = requests.get(api_url, timeout=5)
            if response.status_code == 200:
                data = response.json().get('data', [])[:3] # Limit to 3 results
                vulns.extend([f"CVE: {item['id']} - {item['summary'][:100]}" for item in data])
        except Exception as e:
            pass # Silently handle API error

    return vulns

# Function to check for XSS vulnerabilities
def check_xss(url):
    # Common XSS payloads to test
    payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    # Test each parameter with each payload
    for param in params:
        for payload in payloads:
            # Replace parameter value with payload
            test_url = url.replace(f"{param}={params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
            try:
                response = requests.get(test_url, timeout=5)
                if payload in response.text:
                    return f"XSS vuln in {param} at {url}"
            except Exception as e:
                pass # Silently handle errors

    return None
    
# Function to check for SQL injection vulnerabilities
def check_sqli(url):
    # Common SQL injection payloads
    payloads = ["' OR or '1'='1 --", " UNION SELECT NULL--"]
    # Common SQL error patterns
    errors = ['sql', 'mysql', 'postgresql', 'oracle', 'sqlite']
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    # Test each parameter with each payload
    for param in params:
        for payload in payloads:
            # Replace parameter value with payload
            test_url = url.replace(f"{param}={params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
            try:
                response = requests.get(test_url, timeout=5)
                response_text = response.text.lower()
                # Check for SQL error patterns in response
                if any(error in response_text for error in errors):
                    return f"SQLi vuln in {param} at {url}"
            except Exception as e:
                pass # Silently handle error

    return None
        
# Main function to run vulnerability scan (legacy function for backward compatibility)
def main(target):
    # Use the new VulnerabilityScanner class
    scanner = VulnerabilityScanner(target)
    scanner.scan()
    scanner.display_results()

if __name__ == "__main__":
    target = "scanme.nmap.org"
    if len(sys.argv) >= 2:
        target = sys.argv[1]
    main(target)
