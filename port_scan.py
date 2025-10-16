# Port Scanner Script

# Import libraries
import socket
import time
import errno
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
import re

class PortScanner:
    def __init__(self, target: str, port_range: Tuple[int, int] = (1, 1024),
                 timeout: float = 1.0, max_workers: int = 100):
        
        # Initialize scanner with target, port range, timeout, and max workers
        self.target = target
        self.port_range = port_range
        self.timeout = timeout
        self.max_workers = max_workers
        self.console = Console()
        self.open_ports: Dict[int, str] = {}
        self.results: Dict[int, Dict] = {}
        self.scan_start_time: Optional[float] = None
        self.scan_end_time: Optional[float] = None

    def scan_port(self, port: int) -> Dict:
        result = {
            'port': port,
            'status': 'closed',
            'banner': '',
            'service': 'unknown',
            'error': None
        }
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            connection_result = sock.connect_ex((self.target, port))

            if connection_result == 0:
                result['status'] = 'open'

                banner = self._grab_banner(sock, port)
                result['banner'] = banner.strip() if banner else ''
                result['service'] = self._identify_service(result['banner'],port)

            elif connection_result == errno.ECONNREFUSED:
                result['status'] = 'closed'
            else:
                result['status'] = 'filtered'

        except socket.error as e:
            result['status'] = 'error'
            result['error'] = str(e)
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass

        return result
            
    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        banner = ""
        try:
            sock.settimeout(5.0)
            tls_ports = [443, 993, 995]
            is_tls = port in tls_ports

            if is_tls:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.target)

            if port in [80, 443]:
                request = b"HEAD / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n"
                sock.send(request)
            else:
                pass

            banner_data = sock.recv(1024)
            banner += banner_data.decode('utf-8', errors='ignore')

        except socket.timeout:
            pass
        except Exception as e:
            pass

        return banner
    
    # Identify service based on banner and port
    def _identify_service(self, banner: str, port: int) -> str:
        # Common service by port
        port_services = {
            20: "FTP-DATA",
            21: "FTP",
            22: "SSH",
            23: "TELNET",
            25: "SMTP",
            53: "DNS",
            67: "DHCP",
            68: "DHCP",
            80: "HTTP",
            110: "POP3",
            119: "NNTP",
            123: "NTP",
            135: "MS-RPC",
            139: "NetBIOS-SSN",
            143: "IMAP",
            161: "SNMP",
            162: "SNMP-TRAP",
            179: "BGP",
            389: "LDAP",
            443: "HTTPS",
            445: "Microsoft-DS",
            465: "SMTPS",
            514: "Syslog",
            515: "LPD",
            587: "SMTP",
            631: "IPP",
            993: "IMAPS",
            995: "POP3S",
            1023: "Reserved",
        }

        # Use known service if port matches
        if port in port_services:
            service = port_services[port]
        else:
            service = "unknown"
        
        # Check banner for more details
        banner_lower = banner.lower()
        if "apache" in banner_lower:
            service = "Apache HTTP Server"
        elif "nginx" in banner_lower:
            service = "Nginx"
        elif "iis" in banner_lower or "microsoft-iis" in banner_lower:
            service = "Microsoft IIS"
        elif "openssh" in banner_lower:
            service = "OpenSSH"
        elif "220" in banner_lower and ("ftp" in banner_lower or "filezilla" in banner_lower):
            service = "FTP Server"
        elif "220" in banner_lower and "smtp" in banner_lower:
            service = "SMTP Server"
        elif "+OK" in banner_lower and "pop3" in banner_lower:
            service = "POP3 Server"
        elif "* OK" in banner_lower and "imap" in banner_lower:
            service = "IMAP Server"

        return service
    
    # Main scan function
    def scan_ports_async(self) -> Dict[int, Dict]:
        self.scan_start_time = time.time()
        start_port, end_port = self.port_range
        total_ports = end_port - start_port + 1

        # Print start message
        self.console.print(f"\n[bold purple]Starting port scan on {self.target}[/bold purple]")
        self.console.print(f"Scanning ports {start_port}-{end_port} ({total_ports} ports)\n")

        # Show progress bar
        with Progress() as progress:
            task = progress.add_task("Scanning ports...", total=total_ports)
            # Use thread pool for parallel scans
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                #Submit scans for each port
                future_to_port = {
                    executor.submit(self.scan_port, port): port
                    for port in range(start_port, end_port + 1)
                }
                # Collect results as they complete
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        result = future.result()
                        self.results[port] = result
                    except Exception as e:
                        # Handle errors in scan
                        self.results[port] = {
                            'port': port,
                            'status': 'error',
                            'banner': '',
                            'service': 'unknown',
                            'error': str(e)
                        }
                    # Update progress
                    progress.update(task, advance=1)

        # Record end time
        self.scan_end_time = time.time()
        return self.results
    
    # Display results
    def display_results(self):
        if not self.results:
            self.console.print("[red]No results available. Run scan_ports_async() first.[/red]")
            return
        
        #Count types of ports
        total_ports = len(self.results)
        open_ports = [p for p in self.results.values() if p['status'] == 'open']
        closed_ports = [p for p in self.results.values() if p['status'] == 'closed']
        filtered_ports = [p for p in self.results.values() if p['status'] == 'filtered']
        error_ports = [p for p in self.results.values() if p['status'] == 'error']

        # Calculate scan duration
        scan_duration = self.scan_end_time - self.scan_start_time if self.scan_start_time and self.scan_end_time else 0

        # Summary display
        summary_text = f"""
        [bold] Scan Summary: [/bold]
        Target: [cyan]{self.target}[/cyan]
        Port Range: [cyan]{self.port_range[0]}-{self.port_range[1]}[/cyan]
        Total Ports: [cyan]{total_ports}[/cyan]
        Open Ports: [yellow]{len(open_ports)}[/yellow]
        Closed Ports: [yellow]{len(closed_ports)}[/yellow]
        Filtered Ports: [yellow]{len(filtered_ports)}[/yellow]
        Scan Duration: [cyan]{scan_duration:.2f} seconds[/cyan]
        """
        self.console.print(Panel(summary_text.strip(), title="[bold blue]Port Scan Results[/bold blue]"))

        # Table for open ports
        if open_ports:
            table = Table(title="Open Ports with Service Information")
            table.add_column("Port", style="cyan", justify="right")
            table.add_column("Service", style="green")
            table.add_column("Banner Preview", style="yellow", max_width=50)

            for result in sorted(open_ports, key=lambda x: x['port']):
                port = result['port']
                service = result['service']
                banner_preview = result['banner'][:50] + ("..." if len(result['banner']) > 50 else result['banner'])
                table.add_row(str(port), service, banner_preview)

            self.console.print("\n", table)

            self.console.print(f"\n[green]Scan completed in {scan_duration:.2f} seconds.[/green]\n")


    
if __name__ == "__main__":
    target = "scanme.nmap.org"
    if len(sys.argv) >= 2:
        target = sys.argv[1]
    port_range = (20, 1024)
    if len(sys.argv) >= 4:
        port_range = (int(sys.argv[2]), int(sys.argv[3]))
    scanner = PortScanner(target=target, port_range=port_range, timeout=1.0, max_workers=100)
    scanner.scan_ports_async()
    scanner.display_results()
