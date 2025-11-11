"""Subdomain Enumeration Module"""
import dns.resolver
import requests
import concurrent.futures
import time
from ..utils.logger import get_logger
from ..utils.helpers import is_valid_domain, resolve_domain_to_ip


class SubdomainEnum:
    """Subdomain enumeration and discovery"""

    def __init__(self, config, logger=None):
        """
        Initialize subdomain enumeration module

        Args:
            config: Configuration object
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or get_logger()
        self.max_threads = config.get('general.max_threads', 10)
        self.timeout = config.get('general.timeout', 5)

        # Load wordlist
        self.wordlist = self._load_wordlist()

        # DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = config.get('dns.nameservers', ['8.8.8.8'])
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout

    def _load_wordlist(self):
        """Load subdomain wordlist"""
        # Try to load custom wordlist
        custom_wordlist = self.config.get('subdomain_wordlist.custom_wordlist', '')

        if custom_wordlist:
            try:
                with open(custom_wordlist, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
                self.logger.success(f"Loaded {len(wordlist)} subdomains from custom wordlist")
                return wordlist
            except Exception as e:
                self.logger.warning(f"Could not load custom wordlist: {e}")

        # Use built-in wordlist
        builtin_subdomains = self.config.get('subdomain_wordlist.common_subdomains', [])
        self.logger.info(f"Using built-in wordlist with {len(builtin_subdomains)} subdomains")
        return builtin_subdomains

    def bruteforce_subdomains(self, domain):
        """
        Bruteforce subdomains using wordlist

        Args:
            domain: Target domain

        Returns:
            list: List of discovered subdomains with their IPs
        """
        if not is_valid_domain(domain):
            self.logger.error(f"Invalid domain: {domain}")
            return []

        self.logger.info(f"Bruteforcing subdomains for {domain}")
        discovered = []
        max_subdomains = self.config.get('limits.max_subdomains', 1000)

        # Limit wordlist size
        wordlist = self.wordlist[:max_subdomains]

        def check_subdomain(subdomain_prefix):
            """Check if subdomain exists"""
            subdomain = f"{subdomain_prefix}.{domain}"

            try:
                # Try to resolve
                answers = self.resolver.resolve(subdomain, 'A')
                ips = [str(rdata) for rdata in answers]

                if ips:
                    return {
                        'subdomain': subdomain,
                        'ips': ips
                    }
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
            except Exception as e:
                self.logger.debug(f"Error checking {subdomain}: {e}")

            return None

        # Use thread pool for concurrent checks
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)
                    self.logger.success(f"Found: {result['subdomain']} -> {', '.join(result['ips'])}")

        self.logger.success(f"Discovered {len(discovered)} subdomain(s)")
        return discovered

    def enumerate_via_certificate_transparency(self, domain):
        """
        Enumerate subdomains using Certificate Transparency logs

        Args:
            domain: Target domain

        Returns:
            list: List of subdomains found in CT logs
        """
        self.logger.info(f"Checking Certificate Transparency logs for {domain}")
        subdomains = set()

        try:
            # Use crt.sh API
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()

                for entry in data:
                    name = entry.get('name_value', '')

                    # Split by newline (some entries have multiple names)
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().lower()

                        # Remove wildcard
                        if subdomain.startswith('*.'):
                            subdomain = subdomain[2:]

                        # Only add if it's a subdomain of target domain
                        if subdomain.endswith(domain) and is_valid_domain(subdomain):
                            subdomains.add(subdomain)

                self.logger.success(f"Found {len(subdomains)} subdomain(s) in CT logs")
            else:
                self.logger.warning(f"CT log query returned status code: {response.status_code}")

        except requests.exceptions.Timeout:
            self.logger.warning("Certificate Transparency query timed out")
        except Exception as e:
            self.logger.error(f"Error querying Certificate Transparency logs: {e}")

        return list(subdomains)

    def enumerate_via_virustotal(self, domain, api_key):
        """
        Enumerate subdomains using VirusTotal API

        Args:
            domain: Target domain
            api_key: VirusTotal API key

        Returns:
            list: List of subdomains found
        """
        if not api_key:
            self.logger.warning("VirusTotal API key not provided")
            return []

        self.logger.info(f"Querying VirusTotal for subdomains of {domain}")
        subdomains = set()

        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            headers = {"x-apikey": api_key}

            response = requests.get(url, headers=headers, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()

                for item in data.get('data', []):
                    subdomain = item.get('id', '')
                    if subdomain and is_valid_domain(subdomain):
                        subdomains.add(subdomain)

                self.logger.success(f"Found {len(subdomains)} subdomain(s) via VirusTotal")
            elif response.status_code == 401:
                self.logger.error("VirusTotal API: Invalid API key")
            elif response.status_code == 429:
                self.logger.warning("VirusTotal API: Rate limit exceeded")
            else:
                self.logger.warning(f"VirusTotal API returned status code: {response.status_code}")

        except Exception as e:
            self.logger.error(f"Error querying VirusTotal API: {e}")

        return list(subdomains)

    def enumerate_via_securitytrails(self, domain, api_key):
        """
        Enumerate subdomains using SecurityTrails API

        Args:
            domain: Target domain
            api_key: SecurityTrails API key

        Returns:
            list: List of subdomains found
        """
        if not api_key:
            self.logger.warning("SecurityTrails API key not provided")
            return []

        self.logger.info(f"Querying SecurityTrails for subdomains of {domain}")
        subdomains = set()

        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers = {"APIKEY": api_key}

            response = requests.get(url, headers=headers, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()

                for subdomain_prefix in data.get('subdomains', []):
                    subdomain = f"{subdomain_prefix}.{domain}"
                    if is_valid_domain(subdomain):
                        subdomains.add(subdomain)

                self.logger.success(f"Found {len(subdomains)} subdomain(s) via SecurityTrails")
            elif response.status_code == 401:
                self.logger.error("SecurityTrails API: Invalid API key")
            elif response.status_code == 429:
                self.logger.warning("SecurityTrails API: Rate limit exceeded")
            else:
                self.logger.warning(f"SecurityTrails API returned status code: {response.status_code}")

        except Exception as e:
            self.logger.error(f"Error querying SecurityTrails API: {e}")

        return list(subdomains)

    def verify_subdomains(self, subdomains):
        """
        Verify subdomains and get their IPs

        Args:
            subdomains: List of subdomains to verify

        Returns:
            list: List of verified subdomains with IPs
        """
        self.logger.info(f"Verifying {len(subdomains)} subdomain(s)")
        verified = []

        def verify_subdomain(subdomain):
            """Verify single subdomain"""
            try:
                answers = self.resolver.resolve(subdomain, 'A')
                ips = [str(rdata) for rdata in answers]

                if ips:
                    return {
                        'subdomain': subdomain,
                        'ips': ips
                    }
            except:
                pass
            return None

        # Use thread pool for concurrent verification
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(verify_subdomain, sub): sub for sub in subdomains}

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    verified.append(result)

        self.logger.success(f"Verified {len(verified)} subdomain(s)")
        return verified

    def full_subdomain_enumeration(self, domain):
        """
        Perform comprehensive subdomain enumeration

        Args:
            domain: Target domain

        Returns:
            dict: All discovered subdomains
        """
        self.logger.section(f"Subdomain Enumeration: {domain}")

        all_subdomains = set()
        results = {
            'domain': domain,
            'subdomains': [],
            'sources': {}
        }

        # Method 1: Bruteforce
        if self.config.get('builtin_modules.enabled', True):
            bruteforced = self.bruteforce_subdomains(domain)
            results['sources']['bruteforce'] = bruteforced
            all_subdomains.update([s['subdomain'] for s in bruteforced])

        # Method 2: Certificate Transparency
        if self.config.get('builtin_modules.enabled', True):
            ct_subdomains = self.enumerate_via_certificate_transparency(domain)
            results['sources']['certificate_transparency'] = ct_subdomains
            all_subdomains.update(ct_subdomains)

        # Method 3: VirusTotal API
        if self.config.is_api_enabled('virustotal'):
            vt_api_key = self.config.get_api_key('virustotal')
            vt_subdomains = self.enumerate_via_virustotal(domain, vt_api_key)
            results['sources']['virustotal'] = vt_subdomains
            all_subdomains.update(vt_subdomains)

        # Method 4: SecurityTrails API
        if self.config.is_api_enabled('securitytrails'):
            st_api_key = self.config.get_api_key('securitytrails')
            st_subdomains = self.enumerate_via_securitytrails(domain, st_api_key)
            results['sources']['securitytrails'] = st_subdomains
            all_subdomains.update(st_subdomains)

        # Verify all discovered subdomains
        if all_subdomains:
            # Remove subdomains that were already verified during bruteforce
            bruteforced_subdomains = set([s['subdomain'] for s in results['sources'].get('bruteforce', [])])
            to_verify = all_subdomains - bruteforced_subdomains

            if to_verify:
                verified = self.verify_subdomains(list(to_verify))
                results['subdomains'] = results['sources'].get('bruteforce', []) + verified
            else:
                results['subdomains'] = results['sources'].get('bruteforce', [])
        else:
            results['subdomains'] = []

        self.logger.success(f"Total unique subdomains discovered: {len(results['subdomains'])}")
        return results


if __name__ == "__main__":
    # Test subdomain enumeration module
    from ..utils.config_loader import ConfigLoader

    config = ConfigLoader()
    subdomain_enum = SubdomainEnum(config)

    # Test with a domain
    results = subdomain_enum.full_subdomain_enumeration("google.com")
    print(f"\nDiscovered {len(results['subdomains'])} subdomains")
