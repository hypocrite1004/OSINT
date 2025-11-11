"""Port Scanning and Service Detection Module"""
import socket
import concurrent.futures
from datetime import datetime
from ..utils.logger import get_logger
from ..utils.helpers import is_valid_ip, resolve_domain_to_ip


class PortScanner:
    """Port scanning and service detection"""

    # Common service names for ports
    COMMON_PORTS = {
        20: "FTP Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        587: "SMTP (submission)",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8000: "HTTP Alt",
        8080: "HTTP Proxy",
        8443: "HTTPS Alt",
        8888: "HTTP Alt",
        9090: "HTTP Alt",
        27017: "MongoDB",
    }

    def __init__(self, config, logger=None):
        """
        Initialize port scanner module

        Args:
            config: Configuration object
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or get_logger()
        self.max_threads = config.get('general.max_threads', 10)
        self.timeout = config.get('general.timeout', 2)

        # Get port configuration
        self.common_ports = config.get('limits.common_ports', list(self.COMMON_PORTS.keys()))
        self.port_range = config.get('limits.port_range', '1-1000')
        self.max_ports = config.get('limits.max_ports', 1000)

    def _parse_port_range(self, port_range):
        """
        Parse port range string

        Args:
            port_range: Port range string (e.g., "1-1000" or "80,443,8080")

        Returns:
            list: List of ports to scan
        """
        ports = []

        if ',' in port_range:
            # Comma-separated ports
            for port in port_range.split(','):
                try:
                    ports.append(int(port.strip()))
                except ValueError:
                    pass
        elif '-' in port_range:
            # Port range
            try:
                start, end = port_range.split('-')
                start = int(start.strip())
                end = int(end.strip())
                ports = list(range(start, end + 1))
            except ValueError:
                self.logger.error(f"Invalid port range: {port_range}")
        else:
            # Single port
            try:
                ports = [int(port_range.strip())]
            except ValueError:
                pass

        return ports[:self.max_ports]  # Limit number of ports

    def scan_port(self, host, port):
        """
        Scan a single port

        Args:
            host: Target host (IP or domain)
            port: Port number

        Returns:
            dict: Port scan result or None if closed
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            result = sock.connect_ex((host, port))

            if result == 0:
                # Port is open
                service = self.COMMON_PORTS.get(port, "Unknown")

                # Try to grab banner
                banner = self._grab_banner(host, port)

                sock.close()

                return {
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'banner': banner
                }
            else:
                sock.close()
                return None

        except socket.timeout:
            return None
        except socket.error:
            return None
        except Exception as e:
            self.logger.debug(f"Error scanning port {port}: {e}")
            return None

    def _grab_banner(self, host, port, timeout=2):
        """
        Attempt to grab service banner

        Args:
            host: Target host
            port: Port number
            timeout: Connection timeout

        Returns:
            str: Service banner or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Try to receive banner
            sock.send(b'\r\n')
            banner = sock.recv(1024)
            sock.close()

            if banner:
                return banner.decode('utf-8', errors='ignore').strip()

        except:
            pass

        return None

    def scan_common_ports(self, host):
        """
        Scan common ports on a host

        Args:
            host: Target host (IP or domain)

        Returns:
            list: List of open ports with information
        """
        # Resolve domain to IP if necessary
        if not is_valid_ip(host):
            ip = resolve_domain_to_ip(host)
            if not ip:
                self.logger.error(f"Could not resolve host: {host}")
                return []
            self.logger.info(f"Resolved {host} to {ip}")
            host = ip

        self.logger.info(f"Scanning common ports on {host}")
        open_ports = []

        def scan_port_wrapper(port):
            """Wrapper for thread pool"""
            result = self.scan_port(host, port)
            if result:
                self.logger.success(f"Port {port} is OPEN ({result['service']})")
            return result

        # Use thread pool for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(scan_port_wrapper, port): port for port in self.common_ports}

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)

        self.logger.success(f"Found {len(open_ports)} open port(s)")
        return open_ports

    def scan_port_range(self, host, port_range=None):
        """
        Scan a range of ports on a host

        Args:
            host: Target host (IP or domain)
            port_range: Port range string (uses config default if None)

        Returns:
            list: List of open ports with information
        """
        # Resolve domain to IP if necessary
        if not is_valid_ip(host):
            ip = resolve_domain_to_ip(host)
            if not ip:
                self.logger.error(f"Could not resolve host: {host}")
                return []
            self.logger.info(f"Resolved {host} to {ip}")
            host = ip

        # Use configured port range if not specified
        if port_range is None:
            port_range = self.port_range

        ports = self._parse_port_range(port_range)

        self.logger.info(f"Scanning {len(ports)} ports on {host}")
        open_ports = []

        def scan_port_wrapper(port):
            """Wrapper for thread pool"""
            return self.scan_port(host, port)

        # Use thread pool for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(scan_port_wrapper, port): port for port in ports}

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    self.logger.success(f"Port {result['port']} is OPEN ({result['service']})")

        self.logger.success(f"Found {len(open_ports)} open port(s)")
        return open_ports

    def scan_specific_ports(self, host, ports):
        """
        Scan specific ports on a host

        Args:
            host: Target host (IP or domain)
            ports: List of port numbers or comma-separated string

        Returns:
            list: List of open ports with information
        """
        # Resolve domain to IP if necessary
        if not is_valid_ip(host):
            ip = resolve_domain_to_ip(host)
            if not ip:
                self.logger.error(f"Could not resolve host: {host}")
                return []
            host = ip

        # Parse ports if string
        if isinstance(ports, str):
            ports = self._parse_port_range(ports)

        self.logger.info(f"Scanning {len(ports)} specific ports on {host}")
        open_ports = []

        def scan_port_wrapper(port):
            """Wrapper for thread pool"""
            return self.scan_port(host, port)

        # Use thread pool for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(scan_port_wrapper, port): port for port in ports}

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    self.logger.success(f"Port {result['port']} is OPEN ({result['service']})")

        return open_ports

    def detect_service_version(self, host, port):
        """
        Detect service version on an open port

        Args:
            host: Target host
            port: Port number

        Returns:
            dict: Service version information
        """
        banner = self._grab_banner(host, port, timeout=3)

        service_info = {
            'port': port,
            'service': self.COMMON_PORTS.get(port, "Unknown"),
            'banner': banner,
            'version': None
        }

        # Try to extract version from banner
        if banner:
            # Common version patterns
            if 'SSH' in banner:
                service_info['service'] = 'SSH'
                service_info['version'] = banner
            elif 'FTP' in banner:
                service_info['service'] = 'FTP'
                service_info['version'] = banner
            elif 'Apache' in banner:
                service_info['service'] = 'Apache HTTP Server'
                service_info['version'] = banner
            elif 'nginx' in banner:
                service_info['service'] = 'Nginx HTTP Server'
                service_info['version'] = banner

        return service_info

    def full_port_scan(self, host, scan_type='common'):
        """
        Perform comprehensive port scan

        Args:
            host: Target host (IP or domain)
            scan_type: 'common', 'range', or 'all'

        Returns:
            dict: Complete port scan results
        """
        self.logger.section(f"Port Scanning: {host}")

        results = {
            'host': host,
            'ip': None,
            'scan_type': scan_type,
            'open_ports': [],
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        # Resolve domain to IP
        if not is_valid_ip(host):
            ip = resolve_domain_to_ip(host)
            if not ip:
                self.logger.error(f"Could not resolve host: {host}")
                return results
            results['ip'] = ip
        else:
            results['ip'] = host

        # Perform scan based on type
        if scan_type == 'common':
            results['open_ports'] = self.scan_common_ports(host)
        elif scan_type == 'range':
            results['open_ports'] = self.scan_port_range(host)
        elif scan_type == 'all':
            results['open_ports'] = self.scan_port_range(host, '1-65535')
        else:
            self.logger.error(f"Invalid scan type: {scan_type}")

        return results


if __name__ == "__main__":
    # Test port scanner module
    from ..utils.config_loader import ConfigLoader

    config = ConfigLoader()
    scanner = PortScanner(config)

    # Test with localhost
    results = scanner.full_port_scan("127.0.0.1", scan_type='common')
    print(f"\nOpen ports: {results['open_ports']}")
