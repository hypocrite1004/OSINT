"""WHOIS Lookup Module"""
import whois
import socket
from datetime import datetime
from ..utils.logger import get_logger
from ..utils.helpers import is_valid_domain, is_valid_ip


class WhoisLookup:
    """WHOIS information gathering"""

    def __init__(self, config, logger=None):
        """
        Initialize WHOIS lookup module

        Args:
            config: Configuration object
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or get_logger()
        self.timeout = config.get('general.timeout', 30)

    def lookup_domain(self, domain):
        """
        Perform WHOIS lookup for a domain

        Args:
            domain: Target domain

        Returns:
            dict: WHOIS information
        """
        if not is_valid_domain(domain):
            self.logger.error(f"Invalid domain: {domain}")
            return {}

        self.logger.info(f"Performing WHOIS lookup for {domain}")

        try:
            # Perform WHOIS query
            w = whois.whois(domain)

            # Extract information
            whois_data = {
                'domain_name': self._safe_extract(w.domain_name),
                'registrar': self._safe_extract(w.registrar),
                'whois_server': self._safe_extract(w.whois_server),
                'creation_date': self._format_date(w.creation_date),
                'expiration_date': self._format_date(w.expiration_date),
                'updated_date': self._format_date(w.updated_date),
                'status': self._safe_extract(w.status),
                'name_servers': self._safe_extract(w.name_servers),
                'registrant': self._extract_registrant(w),
                'admin': self._extract_admin(w),
                'tech': self._extract_tech(w),
                'emails': self._safe_extract(w.emails),
                'org': self._safe_extract(w.org),
                'address': self._safe_extract(w.address),
                'city': self._safe_extract(w.city),
                'state': self._safe_extract(w.state),
                'zipcode': self._safe_extract(w.zipcode),
                'country': self._safe_extract(w.country),
                'dnssec': self._safe_extract(w.dnssec),
            }

            self.logger.success(f"WHOIS lookup completed for {domain}")
            return whois_data

        except Exception as e:
            self.logger.error(f"WHOIS lookup failed for {domain}: {e}")
            return {'error': str(e)}

    def _safe_extract(self, value):
        """Safely extract value, handling lists and None"""
        if value is None:
            return None
        if isinstance(value, list):
            # Remove duplicates and return first if only one unique value
            unique_values = list(set([str(v) for v in value if v]))
            if len(unique_values) == 1:
                return unique_values[0]
            return unique_values if unique_values else None
        return str(value)

    def _format_date(self, date_value):
        """Format date value to string"""
        if date_value is None:
            return None

        if isinstance(date_value, list):
            # Get first date if list
            date_value = date_value[0] if date_value else None

        if isinstance(date_value, datetime):
            return date_value.strftime('%Y-%m-%d %H:%M:%S')

        return str(date_value)

    def _extract_registrant(self, w):
        """Extract registrant information"""
        registrant = {}

        if hasattr(w, 'registrant_name') and w.registrant_name:
            registrant['name'] = self._safe_extract(w.registrant_name)
        if hasattr(w, 'registrant_email') and w.registrant_email:
            registrant['email'] = self._safe_extract(w.registrant_email)
        if hasattr(w, 'registrant_phone') and w.registrant_phone:
            registrant['phone'] = self._safe_extract(w.registrant_phone)
        if hasattr(w, 'registrant_organization') and w.registrant_organization:
            registrant['organization'] = self._safe_extract(w.registrant_organization)

        return registrant if registrant else None

    def _extract_admin(self, w):
        """Extract admin contact information"""
        admin = {}

        if hasattr(w, 'admin_name') and w.admin_name:
            admin['name'] = self._safe_extract(w.admin_name)
        if hasattr(w, 'admin_email') and w.admin_email:
            admin['email'] = self._safe_extract(w.admin_email)
        if hasattr(w, 'admin_phone') and w.admin_phone:
            admin['phone'] = self._safe_extract(w.admin_phone)

        return admin if admin else None

    def _extract_tech(self, w):
        """Extract technical contact information"""
        tech = {}

        if hasattr(w, 'tech_name') and w.tech_name:
            tech['name'] = self._safe_extract(w.tech_name)
        if hasattr(w, 'tech_email') and w.tech_email:
            tech['email'] = self._safe_extract(w.tech_email)
        if hasattr(w, 'tech_phone') and w.tech_phone:
            tech['phone'] = self._safe_extract(w.tech_phone)

        return tech if tech else None

    def analyze_whois_data(self, whois_data):
        """
        Analyze WHOIS data for interesting information

        Args:
            whois_data: WHOIS data dictionary

        Returns:
            dict: Analysis results
        """
        if 'error' in whois_data:
            return {'analysis': 'WHOIS lookup failed'}

        analysis = {
            'age_days': None,
            'expires_in_days': None,
            'privacy_protected': False,
            'registrar': whois_data.get('registrar'),
            'name_servers': whois_data.get('name_servers'),
            'status': whois_data.get('status'),
        }

        # Calculate domain age
        creation_date = whois_data.get('creation_date')
        if creation_date:
            try:
                if isinstance(creation_date, str):
                    creation_dt = datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')
                else:
                    creation_dt = creation_date

                age = datetime.now() - creation_dt
                analysis['age_days'] = age.days
                self.logger.info(f"Domain age: {age.days} days")
            except:
                pass

        # Calculate days until expiration
        expiration_date = whois_data.get('expiration_date')
        if expiration_date:
            try:
                if isinstance(expiration_date, str):
                    expiration_dt = datetime.strptime(expiration_date, '%Y-%m-%d %H:%M:%S')
                else:
                    expiration_dt = expiration_date

                days_until_expiry = (expiration_dt - datetime.now()).days
                analysis['expires_in_days'] = days_until_expiry
                self.logger.info(f"Expires in: {days_until_expiry} days")

                if days_until_expiry < 30:
                    self.logger.warning(f"Domain expires soon: {days_until_expiry} days")
            except:
                pass

        # Check for privacy protection
        registrant = whois_data.get('registrant', {})
        if registrant and isinstance(registrant, dict):
            registrant_name = registrant.get('name', '').lower()
            if any(keyword in registrant_name for keyword in ['privacy', 'protected', 'redacted', 'whoisguard']):
                analysis['privacy_protected'] = True
                self.logger.info("Domain has privacy protection enabled")

        return analysis

    def full_whois_lookup(self, domain):
        """
        Perform comprehensive WHOIS lookup with analysis

        Args:
            domain: Target domain

        Returns:
            dict: Complete WHOIS information and analysis
        """
        self.logger.section(f"WHOIS Lookup: {domain}")

        # Perform WHOIS lookup
        whois_data = self.lookup_domain(domain)

        # Analyze data
        analysis = self.analyze_whois_data(whois_data)

        return {
            'whois_data': whois_data,
            'analysis': analysis
        }


if __name__ == "__main__":
    # Test WHOIS lookup module
    from ..utils.config_loader import ConfigLoader

    config = ConfigLoader()
    whois_lookup = WhoisLookup(config)

    # Test with a domain
    results = whois_lookup.full_whois_lookup("google.com")
    print(f"\nWHOIS Data: {results}")
