"""DNS Reconnaissance Module"""
import dns.resolver
import dns.zone
import dns.query
import socket
from ..utils.logger import get_logger
from ..utils.helpers import is_valid_domain, resolve_domain_to_ip


class DNSRecon:
    """DNS reconnaissance and enumeration"""

    def __init__(self, config, logger=None):
        """
        Initialize DNS reconnaissance module

        Args:
            config: Configuration object
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or get_logger()
        self.nameservers = config.get('dns.nameservers', ['8.8.8.8', '8.8.4.4'])
        self.record_types = config.get('dns.record_types', ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'])

        # Configure resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = self.nameservers
        self.resolver.timeout = config.get('general.timeout', 5)
        self.resolver.lifetime = config.get('general.timeout', 5)

    def enumerate_dns_records(self, domain):
        """
        Enumerate DNS records for a domain

        Args:
            domain: Target domain

        Returns:
            dict: DNS records organized by type
        """
        if not is_valid_domain(domain):
            self.logger.error(f"Invalid domain: {domain}")
            return {}

        self.logger.info(f"Enumerating DNS records for {domain}")
        results = {}

        for record_type in self.record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                records = []

                for rdata in answers:
                    record_value = str(rdata)
                    records.append(record_value)
                    self.logger.debug(f"{record_type} record: {record_value}")

                results[record_type] = records
                self.logger.success(f"Found {len(records)} {record_type} record(s)")

            except dns.resolver.NoAnswer:
                self.logger.debug(f"No {record_type} records found for {domain}")
                results[record_type] = []
            except dns.resolver.NXDOMAIN:
                self.logger.error(f"Domain {domain} does not exist")
                return {}
            except dns.resolver.Timeout:
                self.logger.warning(f"DNS query timeout for {record_type} records")
                results[record_type] = []
            except Exception as e:
                self.logger.error(f"Error querying {record_type} records: {e}")
                results[record_type] = []

        return results

    def get_nameservers(self, domain):
        """
        Get nameservers for a domain

        Args:
            domain: Target domain

        Returns:
            list: List of nameservers
        """
        try:
            answers = self.resolver.resolve(domain, 'NS')
            nameservers = [str(rdata) for rdata in answers]
            self.logger.success(f"Found {len(nameservers)} nameserver(s)")
            return nameservers
        except Exception as e:
            self.logger.error(f"Error getting nameservers: {e}")
            return []

    def get_mx_records(self, domain):
        """
        Get MX (Mail Exchange) records for a domain

        Args:
            domain: Target domain

        Returns:
            list: List of MX records with preference
        """
        try:
            answers = self.resolver.resolve(domain, 'MX')
            mx_records = []

            for rdata in answers:
                mx_records.append({
                    'preference': rdata.preference,
                    'exchange': str(rdata.exchange)
                })

            # Sort by preference
            mx_records.sort(key=lambda x: x['preference'])
            self.logger.success(f"Found {len(mx_records)} MX record(s)")
            return mx_records

        except Exception as e:
            self.logger.error(f"Error getting MX records: {e}")
            return []

    def get_txt_records(self, domain):
        """
        Get TXT records for a domain (useful for SPF, DKIM, etc.)

        Args:
            domain: Target domain

        Returns:
            list: List of TXT records
        """
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            txt_records = []

            for rdata in answers:
                txt_value = ''.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                txt_records.append(txt_value)

            self.logger.success(f"Found {len(txt_records)} TXT record(s)")
            return txt_records

        except Exception as e:
            self.logger.error(f"Error getting TXT records: {e}")
            return []

    def zone_transfer(self, domain):
        """
        Attempt DNS zone transfer (AXFR)

        Args:
            domain: Target domain

        Returns:
            list: List of zone records if successful, empty list otherwise
        """
        self.logger.info(f"Attempting zone transfer for {domain}")
        zone_records = []

        # Get nameservers
        nameservers = self.get_nameservers(domain)

        for ns in nameservers:
            try:
                # Remove trailing dot if present
                ns = ns.rstrip('.')

                # Resolve nameserver to IP
                ns_ip = resolve_domain_to_ip(ns)
                if not ns_ip:
                    self.logger.warning(f"Could not resolve nameserver: {ns}")
                    continue

                self.logger.debug(f"Trying zone transfer from {ns} ({ns_ip})")

                # Attempt zone transfer
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))

                if zone:
                    self.logger.success(f"Zone transfer successful from {ns}!")

                    for name, node in zone.nodes.items():
                        zone_records.append({
                            'name': str(name),
                            'records': [str(node)]
                        })

                    return zone_records

            except dns.exception.FormError:
                self.logger.debug(f"Zone transfer refused by {ns}")
            except Exception as e:
                self.logger.debug(f"Zone transfer failed from {ns}: {e}")

        if not zone_records:
            self.logger.info("Zone transfer not allowed (this is normal)")

        return zone_records

    def reverse_dns_lookup(self, ip):
        """
        Perform reverse DNS lookup

        Args:
            ip: IP address

        Returns:
            str: Hostname or None
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.logger.success(f"Reverse DNS: {ip} -> {hostname}")
            return hostname
        except socket.herror:
            self.logger.debug(f"No reverse DNS record for {ip}")
            return None
        except Exception as e:
            self.logger.error(f"Error performing reverse DNS: {e}")
            return None

    def get_soa_record(self, domain):
        """
        Get SOA (Start of Authority) record

        Args:
            domain: Target domain

        Returns:
            dict: SOA record information
        """
        try:
            answers = self.resolver.resolve(domain, 'SOA')
            soa = answers[0]

            soa_info = {
                'mname': str(soa.mname),  # Primary nameserver
                'rname': str(soa.rname),  # Responsible person's email
                'serial': soa.serial,
                'refresh': soa.refresh,
                'retry': soa.retry,
                'expire': soa.expire,
                'minimum': soa.minimum
            }

            self.logger.success("Retrieved SOA record")
            return soa_info

        except Exception as e:
            self.logger.error(f"Error getting SOA record: {e}")
            return {}

    def full_dns_recon(self, domain):
        """
        Perform comprehensive DNS reconnaissance

        Args:
            domain: Target domain

        Returns:
            dict: Complete DNS reconnaissance results
        """
        self.logger.section(f"DNS Reconnaissance: {domain}")

        results = {
            'domain': domain,
            'dns_records': {},
            'nameservers': [],
            'mx_records': [],
            'txt_records': [],
            'soa_record': {},
            'zone_transfer': [],
            'reverse_dns': {}
        }

        # Basic DNS enumeration
        results['dns_records'] = self.enumerate_dns_records(domain)

        # Nameservers
        results['nameservers'] = self.get_nameservers(domain)

        # MX records
        results['mx_records'] = self.get_mx_records(domain)

        # TXT records
        results['txt_records'] = self.get_txt_records(domain)

        # SOA record
        results['soa_record'] = self.get_soa_record(domain)

        # Zone transfer attempt
        if self.config.is_module_enabled('dns_zone_transfer'):
            results['zone_transfer'] = self.zone_transfer(domain)

        # Reverse DNS for A records
        if self.config.is_module_enabled('reverse_dns') and 'A' in results['dns_records']:
            results['reverse_dns'] = {}
            for ip in results['dns_records']['A']:
                hostname = self.reverse_dns_lookup(ip)
                if hostname:
                    results['reverse_dns'][ip] = hostname

        return results


if __name__ == "__main__":
    # Test DNS recon module
    from ..utils.config_loader import ConfigLoader

    config = ConfigLoader()
    dns_recon = DNSRecon(config)

    # Test with a domain
    results = dns_recon.full_dns_recon("google.com")
    print(f"\nDNS Records: {results['dns_records']}")
