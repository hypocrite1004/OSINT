"""External API Integrations Module"""
import requests
import time
from ..utils.logger import get_logger
from ..utils.helpers import is_valid_ip, is_valid_domain


class APIIntegrations:
    """Integration with external OSINT APIs"""

    def __init__(self, config, logger=None):
        """
        Initialize API integrations module

        Args:
            config: Configuration object
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or get_logger()
        self.timeout = config.get('general.timeout', 10)

    def shodan_lookup(self, target):
        """
        Lookup target in Shodan

        Args:
            target: IP address or domain

        Returns:
            dict: Shodan results
        """
        if not self.config.is_api_enabled('shodan'):
            self.logger.debug("Shodan API is not enabled")
            return {'error': 'API not enabled'}

        api_key = self.config.get_api_key('shodan')
        if not api_key:
            self.logger.warning("Shodan API key not configured")
            return {'error': 'API key not configured'}

        self.logger.info(f"Querying Shodan for {target}")

        try:
            # Determine if target is IP or domain
            if is_valid_ip(target):
                url = f"https://api.shodan.io/shodan/host/{target}?key={api_key}"
            else:
                url = f"https://api.shodan.io/dns/resolve?hostnames={target}&key={api_key}"

            response = requests.get(url, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()
                self.logger.success(f"Retrieved Shodan data for {target}")

                # Parse relevant information
                if is_valid_ip(target):
                    result = {
                        'ip': data.get('ip_str'),
                        'hostnames': data.get('hostnames', []),
                        'ports': data.get('ports', []),
                        'vulns': data.get('vulns', []),
                        'os': data.get('os'),
                        'org': data.get('org'),
                        'isp': data.get('isp'),
                        'asn': data.get('asn'),
                        'country': data.get('country_name'),
                        'city': data.get('city'),
                        'services': []
                    }

                    # Extract service information
                    for item in data.get('data', []):
                        service = {
                            'port': item.get('port'),
                            'transport': item.get('transport'),
                            'product': item.get('product'),
                            'version': item.get('version'),
                            'banner': item.get('data', '')[:200]  # Limit banner length
                        }
                        result['services'].append(service)

                    return result
                else:
                    # Domain resolution
                    return data

            elif response.status_code == 401:
                self.logger.error("Shodan API: Invalid API key")
                return {'error': 'Invalid API key'}
            elif response.status_code == 404:
                self.logger.warning(f"Shodan: No information found for {target}")
                return {'error': 'Not found'}
            else:
                self.logger.error(f"Shodan API returned status code: {response.status_code}")
                return {'error': f'API error: {response.status_code}'}

        except requests.exceptions.Timeout:
            self.logger.error("Shodan API request timed out")
            return {'error': 'Timeout'}
        except Exception as e:
            self.logger.error(f"Error querying Shodan: {e}")
            return {'error': str(e)}

    def virustotal_lookup(self, target, target_type='domain'):
        """
        Lookup target in VirusTotal

        Args:
            target: Domain, IP, or URL
            target_type: 'domain', 'ip', or 'url'

        Returns:
            dict: VirusTotal results
        """
        if not self.config.is_api_enabled('virustotal'):
            self.logger.debug("VirusTotal API is not enabled")
            return {'error': 'API not enabled'}

        api_key = self.config.get_api_key('virustotal')
        if not api_key:
            self.logger.warning("VirusTotal API key not configured")
            return {'error': 'API key not configured'}

        self.logger.info(f"Querying VirusTotal for {target}")

        try:
            # Build URL based on target type
            if target_type == 'domain':
                url = f"https://www.virustotal.com/api/v3/domains/{target}"
            elif target_type == 'ip':
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            else:
                self.logger.error(f"Invalid target type: {target_type}")
                return {'error': 'Invalid target type'}

            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})

                self.logger.success(f"Retrieved VirusTotal data for {target}")

                result = {
                    'target': target,
                    'reputation': attributes.get('reputation', 0),
                    'categories': attributes.get('categories', {}),
                    'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                    'last_analysis_date': attributes.get('last_analysis_date'),
                    'whois': attributes.get('whois'),
                }

                # Domain-specific info
                if target_type == 'domain':
                    result['registrar'] = attributes.get('registrar')
                    result['creation_date'] = attributes.get('creation_date')

                # IP-specific info
                if target_type == 'ip':
                    result['asn'] = attributes.get('asn')
                    result['as_owner'] = attributes.get('as_owner')
                    result['country'] = attributes.get('country')

                return result

            elif response.status_code == 401:
                self.logger.error("VirusTotal API: Invalid API key")
                return {'error': 'Invalid API key'}
            elif response.status_code == 404:
                self.logger.warning(f"VirusTotal: No information found for {target}")
                return {'error': 'Not found'}
            elif response.status_code == 429:
                self.logger.warning("VirusTotal API: Rate limit exceeded")
                return {'error': 'Rate limit exceeded'}
            else:
                self.logger.error(f"VirusTotal API returned status code: {response.status_code}")
                return {'error': f'API error: {response.status_code}'}

        except Exception as e:
            self.logger.error(f"Error querying VirusTotal: {e}")
            return {'error': str(e)}

    def haveibeenpwned_check(self, email):
        """
        Check if email has been in a data breach

        Args:
            email: Email address to check

        Returns:
            dict: Breach information
        """
        if not self.config.is_api_enabled('haveibeenpwned'):
            self.logger.debug("HaveIBeenPwned API is not enabled")
            return {'error': 'API not enabled'}

        self.logger.info(f"Checking HaveIBeenPwned for {email}")

        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {
                'User-Agent': self.config.get('user_agent', 'OSINT-Tool'),
            }

            # Add API key if configured (required for some features)
            api_key = self.config.get_api_key('haveibeenpwned')
            if api_key:
                headers['hibp-api-key'] = api_key

            response = requests.get(url, headers=headers, timeout=self.timeout)

            if response.status_code == 200:
                breaches = response.json()
                self.logger.warning(f"Email {email} found in {len(breaches)} breach(es)")

                result = {
                    'email': email,
                    'breach_count': len(breaches),
                    'breaches': []
                }

                for breach in breaches:
                    result['breaches'].append({
                        'name': breach.get('Name'),
                        'domain': breach.get('Domain'),
                        'breach_date': breach.get('BreachDate'),
                        'pwn_count': breach.get('PwnCount'),
                        'description': breach.get('Description', '')[:200],
                        'data_classes': breach.get('DataClasses', [])
                    })

                return result

            elif response.status_code == 404:
                self.logger.success(f"Email {email} not found in any breaches")
                return {'email': email, 'breach_count': 0, 'breaches': []}
            elif response.status_code == 429:
                self.logger.warning("HaveIBeenPwned API: Rate limit exceeded")
                time.sleep(2)  # Rate limiting
                return {'error': 'Rate limit exceeded'}
            else:
                self.logger.error(f"HaveIBeenPwned API returned status code: {response.status_code}")
                return {'error': f'API error: {response.status_code}'}

        except Exception as e:
            self.logger.error(f"Error querying HaveIBeenPwned: {e}")
            return {'error': str(e)}

    def urlscan_lookup(self, url):
        """
        Submit URL to URLScan.io

        Args:
            url: URL to scan

        Returns:
            dict: URLScan results
        """
        if not self.config.is_api_enabled('urlscan'):
            self.logger.debug("URLScan API is not enabled")
            return {'error': 'API not enabled'}

        api_key = self.config.get_api_key('urlscan')
        if not api_key:
            self.logger.warning("URLScan API key not configured")
            return {'error': 'API key not configured'}

        self.logger.info(f"Submitting {url} to URLScan.io")

        try:
            # Submit URL for scanning
            submit_url = "https://urlscan.io/api/v1/scan/"
            headers = {
                'API-Key': api_key,
                'Content-Type': 'application/json'
            }
            data = {'url': url, 'visibility': 'public'}

            response = requests.post(submit_url, headers=headers, json=data, timeout=self.timeout)

            if response.status_code == 200:
                result = response.json()
                scan_id = result.get('uuid')
                result_url = result.get('result')

                self.logger.success(f"URL submitted to URLScan.io: {result_url}")

                return {
                    'scan_id': scan_id,
                    'result_url': result_url,
                    'message': 'Scan submitted successfully. Check result_url for details.'
                }

            elif response.status_code == 429:
                self.logger.warning("URLScan API: Rate limit exceeded")
                return {'error': 'Rate limit exceeded'}
            else:
                self.logger.error(f"URLScan API returned status code: {response.status_code}")
                return {'error': f'API error: {response.status_code}'}

        except Exception as e:
            self.logger.error(f"Error querying URLScan: {e}")
            return {'error': str(e)}

    def ipinfo_lookup(self, ip):
        """
        Get IP geolocation information from IPInfo.io

        Args:
            ip: IP address

        Returns:
            dict: IP information
        """
        if not is_valid_ip(ip):
            self.logger.error(f"Invalid IP address: {ip}")
            return {'error': 'Invalid IP'}

        self.logger.info(f"Looking up IP info for {ip}")

        try:
            # IPInfo.io API
            api_key = self.config.get_api_key('ipinfo')
            if api_key:
                url = f"https://ipinfo.io/{ip}?token={api_key}"
            else:
                url = f"https://ipinfo.io/{ip}"

            response = requests.get(url, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()
                self.logger.success(f"Retrieved IP info for {ip}")

                return {
                    'ip': data.get('ip'),
                    'hostname': data.get('hostname'),
                    'city': data.get('city'),
                    'region': data.get('region'),
                    'country': data.get('country'),
                    'location': data.get('loc'),
                    'org': data.get('org'),
                    'postal': data.get('postal'),
                    'timezone': data.get('timezone')
                }
            else:
                self.logger.error(f"IPInfo API returned status code: {response.status_code}")
                return {'error': f'API error: {response.status_code}'}

        except Exception as e:
            self.logger.error(f"Error querying IPInfo: {e}")
            return {'error': str(e)}


if __name__ == "__main__":
    # Test API integrations
    from ..utils.config_loader import ConfigLoader

    config = ConfigLoader()
    api = APIIntegrations(config)

    # Test IP info lookup (no API key needed)
    result = api.ipinfo_lookup("8.8.8.8")
    print(f"\nIP Info: {result}")
