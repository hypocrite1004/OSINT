"""
Integrated External OSINT Tools Module

This module provides integration with popular open-source OSINT tools:
- theHarvester: Email, subdomain, and host enumeration
- Amass: Advanced subdomain enumeration
- Photon: Web crawler and information extractor
- Sherlock: Social media account finder
"""

import subprocess
import json
import os
import re
from pathlib import Path
from ..utils.logger import get_logger
from ..utils.helpers import is_valid_domain


class IntegratedTools:
    """Integration with external OSINT tools"""

    def __init__(self, config, logger=None):
        """
        Initialize integrated tools module

        Args:
            config: Configuration object
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or get_logger()
        self.tools_available = self._check_tool_availability()

    def _check_tool_availability(self):
        """Check which tools are installed and available"""
        tools = {
            'theharvester': False,
            'amass': False,
            'photon': False,
            'sherlock': False
        }

        # Check theHarvester
        try:
            result = subprocess.run(['theHarvester', '-h'],
                                  capture_output=True,
                                  timeout=5)
            tools['theharvester'] = result.returncode == 0
        except:
            pass

        # Check Amass
        try:
            result = subprocess.run(['amass', '-h'],
                                  capture_output=True,
                                  timeout=5)
            tools['amass'] = result.returncode == 0
        except:
            pass

        # Check Photon (Python package)
        try:
            import photon
            tools['photon'] = True
        except ImportError:
            pass

        # Check Sherlock
        try:
            result = subprocess.run(['sherlock', '--help'],
                                  capture_output=True,
                                  timeout=5)
            tools['sherlock'] = result.returncode == 0
        except:
            pass

        # Log availability
        for tool, available in tools.items():
            if available:
                self.logger.success(f"{tool} is available")
            else:
                self.logger.debug(f"{tool} is not installed")

        return tools

    def run_theharvester(self, domain, data_source='all'):
        """
        Run theHarvester to gather emails, subdomains, and hosts

        Args:
            domain: Target domain
            data_source: Data source to use (all, google, bing, etc.)

        Returns:
            dict: Collected information
        """
        if not self.tools_available.get('theharvester'):
            self.logger.warning("theHarvester is not installed")
            return {'error': 'Tool not installed', 'install': 'pip install theHarvester'}

        if not is_valid_domain(domain):
            self.logger.error(f"Invalid domain: {domain}")
            return {'error': 'Invalid domain'}

        self.logger.info(f"Running theHarvester on {domain}")

        try:
            # Run theHarvester
            cmd = [
                'theHarvester',
                '-d', domain,
                '-b', data_source,
                '-f', f'/tmp/theharvester_{domain}'
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes
            )

            # Parse output
            output = result.stdout

            results = {
                'emails': self._parse_emails_from_harvester(output),
                'hosts': self._parse_hosts_from_harvester(output),
                'ips': self._parse_ips_from_harvester(output),
                'raw_output': output[:1000]  # First 1000 chars
            }

            self.logger.success(f"theHarvester found {len(results['emails'])} emails, {len(results['hosts'])} hosts")
            return results

        except subprocess.TimeoutExpired:
            self.logger.error("theHarvester timeout")
            return {'error': 'Timeout'}
        except Exception as e:
            self.logger.error(f"theHarvester error: {e}")
            return {'error': str(e)}

    def _parse_emails_from_harvester(self, output):
        """Parse emails from theHarvester output"""
        emails = []
        for line in output.split('\n'):
            if '@' in line:
                # Extract email pattern
                matches = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', line)
                emails.extend(matches)
        return list(set(emails))

    def _parse_hosts_from_harvester(self, output):
        """Parse hosts from theHarvester output"""
        hosts = []
        in_hosts_section = False

        for line in output.split('\n'):
            if 'Hosts found' in line or 'hosts found' in line:
                in_hosts_section = True
                continue

            if in_hosts_section and line.strip():
                # Extract hostname
                if ':' in line:
                    host = line.split(':')[0].strip()
                    if '.' in host:
                        hosts.append(host)

        return list(set(hosts))

    def _parse_ips_from_harvester(self, output):
        """Parse IPs from theHarvester output"""
        ips = []
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

        for line in output.split('\n'):
            matches = re.findall(ip_pattern, line)
            ips.extend(matches)

        return list(set(ips))

    def run_amass(self, domain, passive=True):
        """
        Run Amass for advanced subdomain enumeration

        Args:
            domain: Target domain
            passive: Use passive mode (no active scanning)

        Returns:
            dict: Discovered subdomains
        """
        if not self.tools_available.get('amass'):
            self.logger.warning("Amass is not installed")
            return {'error': 'Tool not installed', 'install': 'See https://github.com/OWASP/Amass'}

        if not is_valid_domain(domain):
            self.logger.error(f"Invalid domain: {domain}")
            return {'error': 'Invalid domain'}

        self.logger.info(f"Running Amass on {domain} (passive={passive})")

        try:
            # Prepare command
            if passive:
                cmd = ['amass', 'enum', '-passive', '-d', domain, '-json', '/tmp/amass_output.json']
            else:
                cmd = ['amass', 'enum', '-d', domain, '-json', '/tmp/amass_output.json']

            # Run Amass
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes
            )

            # Parse JSON output
            subdomains = []
            try:
                with open('/tmp/amass_output.json', 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line)
                            if 'name' in data:
                                subdomains.append(data['name'])
                        except:
                            pass
            except:
                # Fallback: parse from stdout
                for line in result.stdout.split('\n'):
                    if domain in line and line.strip():
                        subdomains.append(line.strip())

            results = {
                'subdomains': list(set(subdomains)),
                'count': len(set(subdomains))
            }

            self.logger.success(f"Amass discovered {results['count']} subdomains")
            return results

        except subprocess.TimeoutExpired:
            self.logger.error("Amass timeout")
            return {'error': 'Timeout'}
        except Exception as e:
            self.logger.error(f"Amass error: {e}")
            return {'error': str(e)}

    def run_photon(self, url, depth=2):
        """
        Run Photon web crawler

        Args:
            url: Target URL
            depth: Crawl depth

        Returns:
            dict: Extracted information
        """
        if not self.tools_available.get('photon'):
            self.logger.warning("Photon is not installed")
            return {'error': 'Tool not installed', 'install': 'pip install photon-python'}

        self.logger.info(f"Running Photon on {url}")

        try:
            # Import Photon
            from photon import Photon

            # Initialize Photon
            instance = Photon(
                url=url,
                depth=depth,
                delay=1,
                timeout=10,
                quiet=True
            )

            # Run crawler
            instance.start()

            # Collect results
            results = {
                'urls': list(instance.external),
                'internal_urls': list(instance.internal),
                'files': list(instance.files),
                'intel': list(instance.intel) if hasattr(instance, 'intel') else [],
                'scripts': list(instance.scripts) if hasattr(instance, 'scripts') else [],
                'count': {
                    'urls': len(instance.external),
                    'internal': len(instance.internal),
                    'files': len(instance.files)
                }
            }

            self.logger.success(f"Photon found {results['count']['urls']} external URLs")
            return results

        except ImportError:
            self.logger.error("Photon module not found")
            return {'error': 'Module not found', 'install': 'pip install photon-python'}
        except Exception as e:
            self.logger.error(f"Photon error: {e}")
            return {'error': str(e)}

    def run_sherlock(self, username):
        """
        Run Sherlock to find social media accounts

        Args:
            username: Username to search for

        Returns:
            dict: Found social media accounts
        """
        if not self.tools_available.get('sherlock'):
            self.logger.warning("Sherlock is not installed")
            return {'error': 'Tool not installed', 'install': 'pip install sherlock-project'}

        self.logger.info(f"Running Sherlock for username: {username}")

        try:
            # Run Sherlock
            cmd = [
                'sherlock',
                username,
                '--json',
                '--output', f'/tmp/sherlock_{username}.json'
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes
            )

            # Parse JSON output
            accounts = []
            try:
                with open(f'/tmp/sherlock_{username}.json', 'r') as f:
                    data = json.load(f)

                    for platform, info in data.items():
                        if isinstance(info, dict) and info.get('url_user'):
                            accounts.append({
                                'platform': platform,
                                'url': info['url_user'],
                                'exists': True
                            })
            except:
                # Fallback: parse from stdout
                for line in result.stdout.split('\n'):
                    if 'http' in line:
                        accounts.append({
                            'platform': 'Unknown',
                            'url': line.strip(),
                            'exists': True
                        })

            results = {
                'username': username,
                'accounts': accounts,
                'count': len(accounts)
            }

            self.logger.success(f"Sherlock found {results['count']} accounts for {username}")
            return results

        except subprocess.TimeoutExpired:
            self.logger.error("Sherlock timeout")
            return {'error': 'Timeout'}
        except Exception as e:
            self.logger.error(f"Sherlock error: {e}")
            return {'error': str(e)}

    def run_all_available(self, target, username=None):
        """
        Run all available integrated tools

        Args:
            target: Domain or URL
            username: Optional username for Sherlock

        Returns:
            dict: Results from all tools
        """
        self.logger.section("Running Integrated OSINT Tools")

        results = {
            'target': target,
            'tools_used': [],
            'theharvester': None,
            'amass': None,
            'photon': None,
            'sherlock': None
        }

        # theHarvester
        if self.tools_available.get('theharvester') and is_valid_domain(target):
            results['theharvester'] = self.run_theharvester(target)
            results['tools_used'].append('theHarvester')

        # Amass
        if self.tools_available.get('amass') and is_valid_domain(target):
            results['amass'] = self.run_amass(target)
            results['tools_used'].append('Amass')

        # Photon
        if self.tools_available.get('photon'):
            url = target if target.startswith('http') else f'https://{target}'
            results['photon'] = self.run_photon(url)
            results['tools_used'].append('Photon')

        # Sherlock
        if self.tools_available.get('sherlock') and username:
            results['sherlock'] = self.run_sherlock(username)
            results['tools_used'].append('Sherlock')

        self.logger.success(f"Completed {len(results['tools_used'])} integrated tools")
        return results


if __name__ == "__main__":
    # Test integrated tools
    from ..utils.config_loader import ConfigLoader

    config = ConfigLoader()
    tools = IntegratedTools(config)

    print(f"\nAvailable tools: {tools.tools_available}")
