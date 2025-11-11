#!/usr/bin/env python3
"""
OSINT Collection Tool - Main Entry Point
Comprehensive OSINT automation for penetration testing and security research
"""
import argparse
import sys
import warnings
from pathlib import Path

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from osint_tool.utils.config_loader import ConfigLoader
from osint_tool.utils.logger import Logger
from osint_tool.utils.report_generator import ReportGenerator
from osint_tool.modules.dns_recon import DNSRecon
from osint_tool.modules.whois_lookup import WhoisLookup
from osint_tool.modules.subdomain_enum import SubdomainEnum
from osint_tool.modules.port_scanner import PortScanner
from osint_tool.modules.web_analyzer import WebAnalyzer
from osint_tool.modules.api_integrations import APIIntegrations


class OSINTTool:
    """Main OSINT Collection Tool orchestrator"""

    def __init__(self, config_path=None, verbose=True):
        """
        Initialize OSINT Tool

        Args:
            config_path: Path to configuration file
            verbose: Enable verbose output
        """
        # Load configuration
        self.config = ConfigLoader(config_path)

        # Initialize logger
        self.logger = Logger(verbose=verbose)

        # Initialize modules
        self.dns_recon = DNSRecon(self.config, self.logger)
        self.whois_lookup = WhoisLookup(self.config, self.logger)
        self.subdomain_enum = SubdomainEnum(self.config, self.logger)
        self.port_scanner = PortScanner(self.config, self.logger)
        self.web_analyzer = WebAnalyzer(self.config, self.logger)
        self.api = APIIntegrations(self.config, self.logger)
        self.report_generator = ReportGenerator(self.config, self.logger)

        # Results storage
        self.results = {}

    def collect_all(self, target, scan_ports=True, analyze_web=True):
        """
        Collect all available OSINT information

        Args:
            target: Target domain or IP
            scan_ports: Whether to scan ports
            analyze_web: Whether to analyze web application

        Returns:
            dict: All collected information
        """
        self.logger.banner("OSINT Collection Tool")
        self.logger.info(f"Target: {target}")
        self.logger.info(f"Starting comprehensive OSINT collection...")

        # DNS Reconnaissance
        if self.config.is_module_enabled('dns_enumeration'):
            try:
                self.logger.section("DNS Reconnaissance")
                self.results['dns'] = self.dns_recon.full_dns_recon(target)
            except Exception as e:
                self.logger.error(f"DNS reconnaissance failed: {e}")
                self.results['dns'] = {'error': str(e)}

        # WHOIS Lookup
        if self.config.is_module_enabled('whois_lookup'):
            try:
                self.logger.section("WHOIS Lookup")
                self.results['whois'] = self.whois_lookup.full_whois_lookup(target)
            except Exception as e:
                self.logger.error(f"WHOIS lookup failed: {e}")
                self.results['whois'] = {'error': str(e)}

        # Subdomain Enumeration
        if self.config.is_module_enabled('subdomain_enumeration'):
            try:
                self.logger.section("Subdomain Enumeration")
                self.results['subdomains'] = self.subdomain_enum.full_subdomain_enumeration(target)
            except Exception as e:
                self.logger.error(f"Subdomain enumeration failed: {e}")
                self.results['subdomains'] = {'error': str(e)}

        # Port Scanning
        if scan_ports and self.config.is_module_enabled('port_scanning'):
            try:
                self.logger.section("Port Scanning")
                self.results['ports'] = self.port_scanner.full_port_scan(target, scan_type='common')
            except Exception as e:
                self.logger.error(f"Port scanning failed: {e}")
                self.results['ports'] = {'error': str(e)}

        # Web Analysis
        if analyze_web and self.config.is_module_enabled('web_technology_detection'):
            try:
                self.logger.section("Web Application Analysis")
                self.results['web'] = self.web_analyzer.full_web_analysis(target)
            except Exception as e:
                self.logger.error(f"Web analysis failed: {e}")
                self.results['web'] = {'error': str(e)}

        # External API Queries
        if self.config.get('external_apis.enabled', False):
            self.results['api'] = {}

            # Shodan
            if self.config.is_api_enabled('shodan'):
                try:
                    self.logger.info("Querying Shodan...")
                    self.results['api']['shodan'] = self.api.shodan_lookup(target)
                except Exception as e:
                    self.logger.error(f"Shodan query failed: {e}")

            # VirusTotal
            if self.config.is_api_enabled('virustotal'):
                try:
                    self.logger.info("Querying VirusTotal...")
                    from osint_tool.utils.helpers import is_valid_ip
                    target_type = 'ip' if is_valid_ip(target) else 'domain'
                    self.results['api']['virustotal'] = self.api.virustotal_lookup(target, target_type)
                except Exception as e:
                    self.logger.error(f"VirusTotal query failed: {e}")

            # IP Geolocation
            if self.config.is_module_enabled('ip_geolocation'):
                try:
                    from osint_tool.utils.helpers import is_valid_ip, resolve_domain_to_ip

                    ip = target if is_valid_ip(target) else resolve_domain_to_ip(target)
                    if ip:
                        self.logger.info("Looking up IP geolocation...")
                        self.results['api']['ipinfo'] = self.api.ipinfo_lookup(ip)
                except Exception as e:
                    self.logger.error(f"IP geolocation failed: {e}")

        return self.results

    def save_results(self, target, formats=None):
        """
        Save results to files

        Args:
            target: Target name
            formats: List of output formats

        Returns:
            dict: Paths to saved reports
        """
        if not self.results:
            self.logger.warning("No results to save")
            return {}

        self.logger.info("Generating reports...")

        if formats is None:
            formats = self.config.get('output.formats', ['json', 'html'])

        reports = self.report_generator.generate_reports(self.results, target, formats)

        self.logger.success("All reports generated successfully")
        return reports

    def print_summary(self):
        """Print summary of collected information"""
        self.logger.section("Collection Summary")

        # DNS Summary
        if 'dns' in self.results and 'error' not in self.results['dns']:
            dns_data = self.results['dns']
            self.logger.info(f"DNS Records: {len(dns_data.get('dns_records', {}))} types found")

        # WHOIS Summary
        if 'whois' in self.results and 'error' not in self.results['whois']:
            whois_data = self.results['whois'].get('whois_data', {})
            if 'registrar' in whois_data:
                self.logger.info(f"Registrar: {whois_data['registrar']}")

        # Subdomain Summary
        if 'subdomains' in self.results and 'error' not in self.results['subdomains']:
            subdomains = self.results['subdomains'].get('subdomains', [])
            self.logger.info(f"Subdomains: {len(subdomains)} found")

        # Port Summary
        if 'ports' in self.results and 'error' not in self.results['ports']:
            open_ports = self.results['ports'].get('open_ports', [])
            self.logger.info(f"Open Ports: {len(open_ports)} found")

        # Web Summary
        if 'web' in self.results and 'error' not in self.results['web']:
            technologies = self.results['web'].get('technologies', {})
            tech_count = sum(len(techs) for techs in technologies.values())
            self.logger.info(f"Web Technologies: {tech_count} detected")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='OSINT Collection Tool - Comprehensive OSINT automation for security testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python osint_tool.py -t example.com

  # Scan with all modules
  python osint_tool.py -t example.com --all

  # Scan without port scanning
  python osint_tool.py -t example.com --no-ports

  # Scan without web analysis
  python osint_tool.py -t example.com --no-web

  # Use custom config
  python osint_tool.py -t example.com -c custom_config.yaml

  # Specify output formats
  python osint_tool.py -t example.com -o json html txt

  # Quiet mode (minimal output)
  python osint_tool.py -t example.com -q
        """
    )

    parser.add_argument('-t', '--target', required=True, help='Target domain or IP address')
    parser.add_argument('-c', '--config', help='Path to configuration file')
    parser.add_argument('-o', '--output', nargs='+', choices=['json', 'html', 'txt'],
                        help='Output formats (default: json html)')
    parser.add_argument('--all', action='store_true', help='Enable all modules')
    parser.add_argument('--no-ports', action='store_true', help='Skip port scanning')
    parser.add_argument('--no-web', action='store_true', help='Skip web analysis')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (minimal output)')

    args = parser.parse_args()

    # Determine verbosity
    verbose = not args.quiet
    if args.verbose:
        verbose = True

    try:
        # Initialize tool
        tool = OSINTTool(config_path=args.config, verbose=verbose)

        # Collect information
        scan_ports = not args.no_ports
        analyze_web = not args.no_web

        results = tool.collect_all(
            target=args.target,
            scan_ports=scan_ports,
            analyze_web=analyze_web
        )

        # Print summary
        tool.print_summary()

        # Save results
        output_formats = args.output if args.output else ['json', 'html']
        reports = tool.save_results(args.target, formats=output_formats)

        # Print report locations
        tool.logger.success("\nReports saved:")
        for format_type, filepath in reports.items():
            if filepath:
                tool.logger.result(format_type.upper(), filepath)

        tool.logger.success("\n✓ OSINT collection completed successfully!")

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
