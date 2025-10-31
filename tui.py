# Text-based User Interface for ReaconX

import sys
import subprocess
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from rich.table import Table
from rich.text import Text
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from port_scan import PortScanner
except ImportError as e:
    print(f"Error importing port_scanner: {e}")
    sys.exit(1)

try:
    import vuln_scan
except ImportError as e:
    print(f"Error importing vuln_scanner: {e}")
    sys.exit(1)

# TUI class
class TUIScanner:
    def __init__(self):
        self.console = Console()
        self.options = {
            1: "Port Scan",
            2: "Vulnerability Scan",
            3: "Both Scans",
            4: "Exit"
        }

    # Display the main menu
    def display_menu(self):
        self.console.clear()
        title = Text("Network Security Scanner TUI", style="bold purple")
        self.console.print(Panel(title, title="ReaconX TUI", expand=False))

        # Create menu table
        table = Table(show_header=True, header_style="bold blue")
        table.add_column("Option", style="cyan", justify="right")
        table.add_column("Description", style="green")

        for num, desc in self.options.items():
            table.add_row(str(num), desc)

        self.console.print("\n")
        self.console.print(table)
        self.console.print("\n")

    # Get user's choice with validation
    def get_user_choice(self) -> int:
        while True:
            try:
                choice = IntPrompt.ask("Choose an option (1-4)")
                return choice
            except ValueError:
                self.console.print("[red]Invalid input. Please enter a number between 1 and 4.[/red]")

    # Get target from the user
    def get_target(self) -> str:
        target = ""
        while not target.strip():
            target = Prompt.ask("Enter target (IP address, hostname, or URL)").strip()
            if not target:
                self.console.print("[red]Target cannot be empty.[/red]")
        return target

    # Run port scanner
    def run_port_scan(self, target: str):
        self.console.print(f"\n[bold yellow]Starting Port Scan on {target}[/bold yellow]\n")

        try:
            # Scanner instance
            scanner = PortScanner(
                target=target,
                port_range=(1, 1024),  # Default range, could make configurable later
                timeout=1.0,
                max_workers=100
            )

            # Run scan
            scanner.scan_ports_async()

            # Display results
            scanner.display_results()

        except Exception as e:
            self.console.print(f"[red]Error during port scan: {str(e)}[/red]")

        self.console.print("\n[green]Press Enter to return to main menu...[/green]")
        input()

    # Run vulnerability scan
    def run_vuln_scan(self, target: str):
        self.console.print(f"\n[bold yellow]Starting Vulnerability Scan on {target}[/bold yellow]\n")

        try:
            vuln_scan.main(target)

        except Exception as e:
            self.console.print(f"[red]Error during vulnerability scan: {str(e)}[/red]")

        self.console.print("\n[green]Press Enter to return to main menu...[/green]")
        input()

    # Run both port and vulnerability scans
    def run_both_scans(self, target: str):
        # Port Scan Section
        self.console.print("\n[bold yellow]======= PORT SCAN RESULTS =======[/bold yellow]\n")
        self.run_port_scan(target)

        # Separator
        self.console.print("\n[bold yellow] ======== VULNERABILITY SCAN RESULTS ======== [/bold yellow]\n")

        # Vulnerability Scan Section
        try:
            vuln_scan.main(target)
        except Exception as e:
            self.console.print(f"[red]Error during vulnerability scan: {str(e)}[/red]")

        self.console.print("\n[green]Press Enter to return to main menu...[/green]")
        input()

    # Main TUI 
    def run(self):
        while True:
            self.display_menu()
            choice = self.get_user_choice()

            if choice == 4:  # Exit
                self.console.print("[bold cyan]Thank you for using ReaconX TUI![/bold cyan]")
                sys.exit(0)

            target = self.get_target()

            if choice == 1:
                self.run_port_scan(target)
            elif choice == 2:
                self.run_vuln_scan(target)
            elif choice == 3:
                self.run_both_scans(target)


def main():
    # Check if running as main module
    scanner = TUIScanner()
    scanner.run()


if __name__ == "__main__":
    main()
