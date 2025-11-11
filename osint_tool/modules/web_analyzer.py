"""Web Technology Stack Analysis Module"""
import requests
import ssl
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import re
from datetime import datetime
from ..utils.logger import get_logger
from ..utils.helpers import extract_emails_from_text, extract_urls_from_text


class WebAnalyzer:
    """Web application technology detection and analysis"""

    def __init__(self, config, logger=None):
        """
        Initialize web analyzer module

        Args:
            config: Configuration object
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or get_logger()
        self.timeout = config.get('general.timeout', 10)
        self.user_agent = config.get('user_agent', 'Mozilla/5.0')

        # Technology signatures
        self.tech_signatures = self._load_tech_signatures()

    def _load_tech_signatures(self):
        """Load technology detection signatures"""
        return {
            # Web servers
            'servers': {
                'Apache': [r'Apache[/\s]', r'Apache$'],
                'Nginx': [r'nginx[/\s]', r'nginx$'],
                'Microsoft-IIS': [r'Microsoft-IIS[/\s]'],
                'LiteSpeed': [r'LiteSpeed'],
                'Cloudflare': [r'cloudflare'],
            },
            # Programming languages/frameworks
            'frameworks': {
                'PHP': [r'\.php', r'X-Powered-By.*PHP', r'PHPSESSID'],
                'ASP.NET': [r'ASP\.NET', r'ASPSESSION', r'\.aspx'],
                'Django': [r'django', r'csrftoken'],
                'Flask': [r'Flask'],
                'Ruby on Rails': [r'Rails', r'_session_id'],
                'Node.js': [r'Express', r'X-Powered-By.*Express'],
                'Laravel': [r'laravel', r'laravel_session'],
                'WordPress': [r'wp-content', r'wp-includes', r'WordPress'],
                'Joomla': [r'Joomla', r'/components/com_'],
                'Drupal': [r'Drupal', r'sites/default/files'],
            },
            # JavaScript libraries
            'javascript': {
                'jQuery': [r'jquery[.-]', r'/jquery\.js'],
                'React': [r'react[.-]', r'_react'],
                'Angular': [r'angular[.-]', r'ng-'],
                'Vue.js': [r'vue[.-]js', r'__vue__'],
                'Bootstrap': [r'bootstrap[.-]'],
            },
            # CMS/Platforms
            'cms': {
                'WordPress': [r'wp-content', r'wp-includes'],
                'Shopify': [r'shopify', r'cdn\.shopify\.com'],
                'Wix': [r'wix\.com', r'parastorage\.com'],
                'Squarespace': [r'squarespace'],
            },
            # CDN/Services
            'cdn': {
                'Cloudflare': [r'cloudflare', r'__cfduid'],
                'Amazon CloudFront': [r'cloudfront\.net'],
                'Fastly': [r'fastly'],
                'Akamai': [r'akamai'],
            }
        }

    def fetch_website(self, url):
        """
        Fetch website content

        Args:
            url: Target URL

        Returns:
            dict: Response data including headers and content
        """
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        self.logger.info(f"Fetching {url}")

        try:
            headers = {'User-Agent': self.user_agent}
            response = requests.get(url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)

            return {
                'url': response.url,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text,
                'cookies': dict(response.cookies),
                'redirected': response.url != url,
                'final_url': response.url
            }

        except requests.exceptions.SSLError:
            self.logger.warning(f"SSL error accessing {url}, trying without verification")
            try:
                response = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
                return {
                    'url': url,
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'content': response.text,
                    'ssl_error': True
                }
            except Exception as e:
                self.logger.error(f"Error fetching {url}: {e}")
                return {'error': str(e)}

        except Exception as e:
            self.logger.error(f"Error fetching {url}: {e}")
            return {'error': str(e)}

    def detect_technologies(self, response_data):
        """
        Detect web technologies from response data

        Args:
            response_data: Response data from fetch_website

        Returns:
            dict: Detected technologies
        """
        if 'error' in response_data:
            return {}

        self.logger.info("Detecting web technologies")
        detected = {
            'servers': [],
            'frameworks': [],
            'javascript': [],
            'cms': [],
            'cdn': []
        }

        headers = response_data.get('headers', {})
        content = response_data.get('content', '')
        cookies = response_data.get('cookies', {})

        # Combine all text for pattern matching
        all_text = str(headers) + content + str(cookies)

        # Check each technology category
        for category, techs in self.tech_signatures.items():
            for tech_name, patterns in techs.items():
                for pattern in patterns:
                    if re.search(pattern, all_text, re.IGNORECASE):
                        if tech_name not in detected[category]:
                            detected[category].append(tech_name)
                            self.logger.success(f"Detected: {tech_name}")
                        break

        return detected

    def extract_metadata(self, response_data):
        """
        Extract metadata from HTML

        Args:
            response_data: Response data from fetch_website

        Returns:
            dict: Extracted metadata
        """
        if 'error' in response_data:
            return {}

        content = response_data.get('content', '')
        soup = BeautifulSoup(content, 'html.parser')

        metadata = {
            'title': None,
            'description': None,
            'keywords': None,
            'author': None,
            'generator': None,
            'og_tags': {},
            'twitter_tags': {}
        }

        # Extract title
        title_tag = soup.find('title')
        if title_tag:
            metadata['title'] = title_tag.text.strip()

        # Extract meta tags
        for meta in soup.find_all('meta'):
            name = meta.get('name', '').lower()
            property_attr = meta.get('property', '').lower()
            content = meta.get('content', '')

            if name == 'description':
                metadata['description'] = content
            elif name == 'keywords':
                metadata['keywords'] = content
            elif name == 'author':
                metadata['author'] = content
            elif name == 'generator':
                metadata['generator'] = content

            # Open Graph tags
            if property_attr.startswith('og:'):
                metadata['og_tags'][property_attr] = content

            # Twitter Card tags
            if name.startswith('twitter:'):
                metadata['twitter_tags'][name] = content

        self.logger.success("Extracted metadata from HTML")
        return metadata

    def analyze_ssl_certificate(self, domain):
        """
        Analyze SSL/TLS certificate

        Args:
            domain: Target domain

        Returns:
            dict: SSL certificate information
        """
        self.logger.info(f"Analyzing SSL certificate for {domain}")

        # Remove protocol if present
        if '://' in domain:
            domain = urlparse(domain).netloc

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    ssl_info = {
                        'subject': dict(x[0] for x in cert.get('subject', ())),
                        'issuer': dict(x[0] for x in cert.get('issuer', ())),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'san': [],
                        'protocol': ssock.version()
                    }

                    # Extract Subject Alternative Names
                    for item in cert.get('subjectAltName', []):
                        if item[0] == 'DNS':
                            ssl_info['san'].append(item[1])

                    self.logger.success(f"Retrieved SSL certificate info")
                    return ssl_info

        except socket.timeout:
            self.logger.warning(f"SSL connection timeout for {domain}")
            return {'error': 'Timeout'}
        except Exception as e:
            self.logger.error(f"Error analyzing SSL certificate: {e}")
            return {'error': str(e)}

    def extract_links(self, response_data):
        """
        Extract links from HTML

        Args:
            response_data: Response data from fetch_website

        Returns:
            dict: Extracted links categorized by type
        """
        if 'error' in response_data:
            return {}

        content = response_data.get('content', '')
        base_url = response_data.get('url', '')
        soup = BeautifulSoup(content, 'html.parser')

        links = {
            'internal': [],
            'external': [],
            'javascript': [],
            'css': [],
            'images': [],
            'forms': []
        }

        # Extract base domain
        base_domain = urlparse(base_url).netloc

        # Extract all links
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if href.startswith(('http://', 'https://')):
                if base_domain in href:
                    links['internal'].append(href)
                else:
                    links['external'].append(href)

        # Extract JavaScript files
        for script in soup.find_all('script', src=True):
            links['javascript'].append(script['src'])

        # Extract CSS files
        for link in soup.find_all('link', rel='stylesheet'):
            if link.get('href'):
                links['css'].append(link['href'])

        # Extract images
        for img in soup.find_all('img', src=True):
            links['images'].append(img['src'])

        # Extract forms
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }

            for input_tag in form.find_all('input'):
                form_data['inputs'].append({
                    'name': input_tag.get('name'),
                    'type': input_tag.get('type', 'text')
                })

            links['forms'].append(form_data)

        self.logger.success(f"Extracted links from HTML")
        return links

    def extract_emails_and_contacts(self, response_data):
        """
        Extract emails and contact information

        Args:
            response_data: Response data from fetch_website

        Returns:
            dict: Extracted contact information
        """
        if 'error' in response_data:
            return {}

        content = response_data.get('content', '')

        contacts = {
            'emails': extract_emails_from_text(content),
            'phones': [],
            'social_media': []
        }

        # Extract phone numbers
        phone_pattern = r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
        phones = re.findall(phone_pattern, content)
        contacts['phones'] = list(set([''.join(p) for p in phones]))

        # Extract social media links
        social_patterns = {
            'facebook': r'facebook\.com/[\w.-]+',
            'twitter': r'twitter\.com/[\w.-]+',
            'linkedin': r'linkedin\.com/(in|company)/[\w.-]+',
            'instagram': r'instagram\.com/[\w.-]+',
            'github': r'github\.com/[\w.-]+',
        }

        for platform, pattern in social_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                contacts['social_media'].append({
                    'platform': platform,
                    'url': f"https://{match}"
                })

        self.logger.success(f"Extracted {len(contacts['emails'])} email(s)")
        return contacts

    def full_web_analysis(self, target):
        """
        Perform comprehensive web analysis

        Args:
            target: Target URL or domain

        Returns:
            dict: Complete web analysis results
        """
        self.logger.section(f"Web Analysis: {target}")

        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            # Try HTTPS first
            target = 'https://' + target

        results = {
            'target': target,
            'response': {},
            'technologies': {},
            'metadata': {},
            'ssl_certificate': {},
            'links': {},
            'contacts': {},
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        # Fetch website
        response_data = self.fetch_website(target)
        results['response'] = {
            'status_code': response_data.get('status_code'),
            'final_url': response_data.get('final_url'),
            'headers': response_data.get('headers', {}),
            'redirected': response_data.get('redirected', False)
        }

        if 'error' not in response_data:
            # Detect technologies
            results['technologies'] = self.detect_technologies(response_data)

            # Extract metadata
            results['metadata'] = self.extract_metadata(response_data)

            # Extract links
            results['links'] = self.extract_links(response_data)

            # Extract contacts
            results['contacts'] = self.extract_emails_and_contacts(response_data)

        # Analyze SSL certificate (for HTTPS)
        if target.startswith('https://'):
            domain = urlparse(target).netloc
            results['ssl_certificate'] = self.analyze_ssl_certificate(domain)

        return results


if __name__ == "__main__":
    # Test web analyzer module
    from ..utils.config_loader import ConfigLoader

    config = ConfigLoader()
    analyzer = WebAnalyzer(config)

    # Test with a website
    results = analyzer.full_web_analysis("example.com")
    print(f"\nWeb Analysis Results: {results['technologies']}")
