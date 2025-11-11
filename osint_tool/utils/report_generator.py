"""Report Generation Utility"""
import json
import os
from datetime import datetime
from pathlib import Path
from jinja2 import Template
from ..utils.logger import get_logger
from ..utils.helpers import sanitize_filename


class ReportGenerator:
    """Generate reports in various formats"""

    def __init__(self, config, logger=None):
        """
        Initialize report generator

        Args:
            config: Configuration object
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or get_logger()
        self.output_dir = Path(config.get('output.directory', './reports'))
        self.timestamp = config.get('output.timestamp', True)

        # Create output directory if it doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _generate_filename(self, target, format_type):
        """
        Generate filename for report

        Args:
            target: Target name
            format_type: Report format (json, html, txt)

        Returns:
            str: Generated filename
        """
        # Sanitize target name
        safe_target = sanitize_filename(target)

        if self.timestamp:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{safe_target}_{timestamp}.{format_type}"
        else:
            filename = f"{safe_target}.{format_type}"

        return self.output_dir / filename

    def save_json(self, data, target):
        """
        Save results as JSON

        Args:
            data: Data to save
            target: Target name

        Returns:
            str: Path to saved file
        """
        filepath = self._generate_filename(target, 'json')

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            self.logger.success(f"JSON report saved: {filepath}")
            return str(filepath)

        except Exception as e:
            self.logger.error(f"Error saving JSON report: {e}")
            return None

    def save_txt(self, data, target):
        """
        Save results as plain text

        Args:
            data: Data to save
            target: Target name

        Returns:
            str: Path to saved file
        """
        filepath = self._generate_filename(target, 'txt')

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write(f"OSINT Collection Report\n")
                f.write(f"Target: {target}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")

                # Write data sections
                self._write_section(f, data)

            self.logger.success(f"Text report saved: {filepath}")
            return str(filepath)

        except Exception as e:
            self.logger.error(f"Error saving text report: {e}")
            return None

    def _write_section(self, file, data, indent=0):
        """Recursively write data sections to text file"""
        indent_str = "  " * indent

        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    file.write(f"{indent_str}{key}:\n")
                    self._write_section(file, value, indent + 1)
                else:
                    file.write(f"{indent_str}{key}: {value}\n")
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    file.write(f"{indent_str}[{i}]:\n")
                    self._write_section(file, item, indent + 1)
                else:
                    file.write(f"{indent_str}- {item}\n")
        else:
            file.write(f"{indent_str}{data}\n")

    def save_html(self, data, target):
        """
        Save results as HTML

        Args:
            data: Data to save
            target: Target name

        Returns:
            str: Path to saved file
        """
        filepath = self._generate_filename(target, 'html')

        try:
            html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Report - {{ target }}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .header .subtitle {
            opacity: 0.9;
            margin-top: 10px;
        }
        .section {
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .section h2 {
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-top: 0;
        }
        .section h3 {
            color: #764ba2;
            margin-top: 20px;
        }
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        .data-table th, .data-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .data-table th {
            background-color: #667eea;
            color: white;
        }
        .data-table tr:hover {
            background-color: #f5f5f5;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            margin: 2px;
        }
        .badge-success {
            background-color: #10b981;
            color: white;
        }
        .badge-warning {
            background-color: #f59e0b;
            color: white;
        }
        .badge-info {
            background-color: #3b82f6;
            color: white;
        }
        .list-item {
            padding: 8px;
            border-left: 3px solid #667eea;
            margin: 5px 0;
            background-color: #f8f9fa;
        }
        pre {
            background-color: #f4f4f4;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 OSINT Collection Report</h1>
        <div class="subtitle">
            <strong>Target:</strong> {{ target }}<br>
            <strong>Generated:</strong> {{ timestamp }}
        </div>
    </div>

    {% if dns_data %}
    <div class="section">
        <h2>📡 DNS Information</h2>
        {% if dns_data.dns_records %}
            <h3>DNS Records</h3>
            {% for record_type, records in dns_data.dns_records.items() %}
                {% if records %}
                    <strong>{{ record_type }} Records:</strong>
                    {% for record in records %}
                        <div class="list-item">{{ record }}</div>
                    {% endfor %}
                {% endif %}
            {% endfor %}
        {% endif %}

        {% if dns_data.nameservers %}
            <h3>Nameservers</h3>
            {% for ns in dns_data.nameservers %}
                <div class="list-item">{{ ns }}</div>
            {% endfor %}
        {% endif %}
    </div>
    {% endif %}

    {% if whois_data %}
    <div class="section">
        <h2>🌐 WHOIS Information</h2>
        <table class="data-table">
            {% if whois_data.whois_data %}
                {% for key, value in whois_data.whois_data.items() %}
                    {% if value and key != 'error' %}
                        <tr>
                            <th>{{ key }}</th>
                            <td>{{ value }}</td>
                        </tr>
                    {% endif %}
                {% endfor %}
            {% endif %}
        </table>
    </div>
    {% endif %}

    {% if subdomains %}
    <div class="section">
        <h2>🔗 Subdomains</h2>
        <p><strong>Total discovered:</strong> {{ subdomains|length }}</p>
        {% for subdomain in subdomains %}
            <div class="list-item">
                <strong>{{ subdomain.subdomain }}</strong><br>
                IPs: {{ subdomain.ips|join(', ') }}
            </div>
        {% endfor %}
    </div>
    {% endif %}

    {% if ports %}
    <div class="section">
        <h2>🔓 Open Ports</h2>
        <table class="data-table">
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Banner</th>
                </tr>
            </thead>
            <tbody>
                {% for port in ports %}
                    <tr>
                        <td><span class="badge badge-success">{{ port.port }}</span></td>
                        <td>{{ port.service }}</td>
                        <td>{{ port.banner or 'N/A' }}</td>
                    </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    {% if web_data %}
    <div class="section">
        <h2>🌐 Web Analysis</h2>

        {% if web_data.technologies %}
            <h3>Detected Technologies</h3>
            {% for category, techs in web_data.technologies.items() %}
                {% if techs %}
                    <strong>{{ category|capitalize }}:</strong><br>
                    {% for tech in techs %}
                        <span class="badge badge-info">{{ tech }}</span>
                    {% endfor %}
                    <br><br>
                {% endif %}
            {% endfor %}
        {% endif %}

        {% if web_data.contacts and web_data.contacts.emails %}
            <h3>Contact Information</h3>
            <strong>Emails:</strong>
            {% for email in web_data.contacts.emails %}
                <div class="list-item">{{ email }}</div>
            {% endfor %}
        {% endif %}
    </div>
    {% endif %}

    <div class="footer">
        Generated by OSINT Collection Tool<br>
        For authorized security testing and research purposes only
    </div>
</body>
</html>
            """

            template = Template(html_template)

            # Prepare data for template
            context = {
                'target': target,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'dns_data': data.get('dns'),
                'whois_data': data.get('whois'),
                'subdomains': data.get('subdomains', {}).get('subdomains', []),
                'ports': data.get('ports', {}).get('open_ports', []),
                'web_data': data.get('web'),
            }

            html_content = template.render(**context)

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)

            self.logger.success(f"HTML report saved: {filepath}")
            return str(filepath)

        except Exception as e:
            self.logger.error(f"Error saving HTML report: {e}")
            return None

    def generate_reports(self, data, target, formats=None):
        """
        Generate reports in multiple formats

        Args:
            data: Data to save
            target: Target name
            formats: List of formats (json, html, txt). If None, uses config

        Returns:
            dict: Paths to generated reports
        """
        if formats is None:
            formats = self.config.get('output.formats', ['json'])

        reports = {}

        for format_type in formats:
            if format_type == 'json':
                reports['json'] = self.save_json(data, target)
            elif format_type == 'html':
                reports['html'] = self.save_html(data, target)
            elif format_type == 'txt':
                reports['txt'] = self.save_txt(data, target)
            else:
                self.logger.warning(f"Unknown report format: {format_type}")

        return reports


if __name__ == "__main__":
    # Test report generator
    from ..config_loader import ConfigLoader

    config = ConfigLoader()
    generator = ReportGenerator(config)

    # Test data
    test_data = {
        'dns': {
            'dns_records': {
                'A': ['93.184.216.34'],
                'MX': ['mail.example.com']
            },
            'nameservers': ['ns1.example.com', 'ns2.example.com']
        },
        'whois': {
            'whois_data': {
                'registrar': 'Example Registrar',
                'creation_date': '2020-01-01'
            }
        }
    }

    reports = generator.generate_reports(test_data, 'example.com', formats=['json', 'html', 'txt'])
    print(f"Generated reports: {reports}")
