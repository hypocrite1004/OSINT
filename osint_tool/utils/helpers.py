"""Helper utility functions"""
import re
import socket
import ipaddress
from urllib.parse import urlparse
import time
from functools import wraps


def is_valid_domain(domain):
    """
    Check if a string is a valid domain name

    Args:
        domain: Domain name to validate

    Returns:
        bool: True if valid domain, False otherwise
    """
    if not domain or len(domain) > 253:
        return False

    # Remove protocol if present
    if '://' in domain:
        domain = urlparse(domain).netloc

    # Domain pattern
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9]'  # First character
        r'(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'  # Sub domain
        r'+[a-zA-Z]{2,}$'  # Top level domain
    )

    return bool(pattern.match(domain))


def is_valid_ip(ip):
    """
    Check if a string is a valid IP address (IPv4 or IPv6)

    Args:
        ip: IP address to validate

    Returns:
        bool: True if valid IP, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_email(email):
    """
    Check if a string is a valid email address

    Args:
        email: Email address to validate

    Returns:
        bool: True if valid email, False otherwise
    """
    pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    return bool(pattern.match(email))


def extract_domain_from_url(url):
    """
    Extract domain from URL

    Args:
        url: URL string

    Returns:
        str: Domain name or None
    """
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return None


def resolve_domain_to_ip(domain):
    """
    Resolve domain name to IP address

    Args:
        domain: Domain name

    Returns:
        str: IP address or None
    """
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def reverse_dns_lookup(ip):
    """
    Perform reverse DNS lookup

    Args:
        ip: IP address

    Returns:
        str: Hostname or None
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


def extract_emails_from_text(text):
    """
    Extract email addresses from text

    Args:
        text: Text to search

    Returns:
        list: List of email addresses found
    """
    pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    return list(set(pattern.findall(text)))


def extract_urls_from_text(text):
    """
    Extract URLs from text

    Args:
        text: Text to search

    Returns:
        list: List of URLs found
    """
    pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    return list(set(pattern.findall(text)))


def clean_domain(domain):
    """
    Clean and normalize domain name

    Args:
        domain: Domain name to clean

    Returns:
        str: Cleaned domain name
    """
    # Remove protocol
    if '://' in domain:
        domain = urlparse(domain).netloc

    # Remove port
    if ':' in domain:
        domain = domain.split(':')[0]

    # Remove path
    if '/' in domain:
        domain = domain.split('/')[0]

    # Convert to lowercase
    domain = domain.lower().strip()

    # Remove www prefix
    if domain.startswith('www.'):
        domain = domain[4:]

    return domain


def get_domain_variations(domain):
    """
    Get common variations of a domain

    Args:
        domain: Base domain

    Returns:
        list: List of domain variations
    """
    variations = [
        domain,
        f"www.{domain}",
        f"mail.{domain}",
        f"ftp.{domain}",
        f"webmail.{domain}",
        f"smtp.{domain}",
        f"pop.{domain}",
        f"api.{domain}",
        f"dev.{domain}",
        f"staging.{domain}",
        f"test.{domain}",
        f"admin.{domain}",
        f"portal.{domain}",
        f"m.{domain}",
        f"mobile.{domain}",
    ]
    return variations


def retry_on_failure(max_retries=3, delay=1, backoff=2):
    """
    Decorator to retry function on failure

    Args:
        max_retries: Maximum number of retries
        delay: Initial delay between retries (seconds)
        backoff: Multiplier for delay after each retry

    Returns:
        Decorated function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            current_delay = delay

            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    retries += 1
                    if retries >= max_retries:
                        raise e
                    time.sleep(current_delay)
                    current_delay *= backoff

            return None
        return wrapper
    return decorator


def sanitize_filename(filename):
    """
    Sanitize filename to remove invalid characters

    Args:
        filename: Original filename

    Returns:
        str: Sanitized filename
    """
    # Remove invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing spaces and dots
    filename = filename.strip(' .')
    return filename


def format_bytes(bytes_size):
    """
    Format bytes to human readable format

    Args:
        bytes_size: Size in bytes

    Returns:
        str: Formatted size string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} PB"


def get_base_domain(domain):
    """
    Extract base domain from subdomain

    Args:
        domain: Full domain (e.g., sub.example.com)

    Returns:
        str: Base domain (e.g., example.com)
    """
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


if __name__ == "__main__":
    # Test helper functions
    print("Testing helper functions:")
    print(f"Valid domain (google.com): {is_valid_domain('google.com')}")
    print(f"Valid IP (8.8.8.8): {is_valid_ip('8.8.8.8')}")
    print(f"Valid email (test@example.com): {is_valid_email('test@example.com')}")
    print(f"Clean domain: {clean_domain('https://www.example.com:443/path')}")
    print(f"Base domain: {get_base_domain('sub.example.com')}")
