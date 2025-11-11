"""Logging utility with color support"""
import sys
from datetime import datetime
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)


class Logger:
    """Custom logger with colored output"""

    def __init__(self, verbose=True, log_file=None):
        """
        Initialize logger

        Args:
            verbose: Enable verbose output
            log_file: Optional file path to save logs
        """
        self.verbose = verbose
        self.log_file = log_file

        if self.log_file:
            # Create log file
            with open(self.log_file, 'w', encoding='utf-8') as f:
                f.write(f"=== OSINT Tool Log - {datetime.now()} ===\n\n")

    def _log(self, level, message, color=''):
        """Internal logging method"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {message}"

        # Print to console with color
        if color:
            print(f"{color}{log_message}{Style.RESET_ALL}")
        else:
            print(log_message)

        # Write to file if enabled
        if self.log_file:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_message + '\n')

    def info(self, message):
        """Log info message"""
        if self.verbose:
            self._log("INFO", message, Fore.CYAN)

    def success(self, message):
        """Log success message"""
        self._log("SUCCESS", message, Fore.GREEN)

    def warning(self, message):
        """Log warning message"""
        self._log("WARNING", message, Fore.YELLOW)

    def error(self, message):
        """Log error message"""
        self._log("ERROR", message, Fore.RED)

    def critical(self, message):
        """Log critical message"""
        self._log("CRITICAL", message, Fore.WHITE + Back.RED)

    def debug(self, message):
        """Log debug message"""
        if self.verbose:
            self._log("DEBUG", message, Fore.MAGENTA)

    def banner(self, text):
        """Print a banner"""
        border = "=" * (len(text) + 4)
        print(f"\n{Fore.CYAN}{border}")
        print(f"  {text}")
        print(f"{border}{Style.RESET_ALL}\n")

    def section(self, text):
        """Print a section header"""
        print(f"\n{Fore.YELLOW}{'─' * 50}")
        print(f"  {text}")
        print(f"{'─' * 50}{Style.RESET_ALL}\n")

    def result(self, key, value):
        """Print a key-value result"""
        print(f"{Fore.WHITE}{key}:{Style.RESET_ALL} {Fore.GREEN}{value}{Style.RESET_ALL}")

    def list_item(self, item, prefix="  •"):
        """Print a list item"""
        print(f"{Fore.WHITE}{prefix} {Fore.CYAN}{item}{Style.RESET_ALL}")


# Global logger instance
_logger = None


def get_logger(verbose=True, log_file=None):
    """Get or create global logger instance"""
    global _logger
    if _logger is None:
        _logger = Logger(verbose=verbose, log_file=log_file)
    return _logger


if __name__ == "__main__":
    # Test logger
    logger = Logger(verbose=True)
    logger.banner("OSINT Collection Tool")
    logger.info("This is an info message")
    logger.success("This is a success message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.debug("This is a debug message")
    logger.section("Test Section")
    logger.result("Target", "example.com")
    logger.list_item("Item 1")
    logger.list_item("Item 2")
