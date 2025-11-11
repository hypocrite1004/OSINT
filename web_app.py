#!/usr/bin/env python3
"""
OSINT Collection Tool - Web Interface
Flask-based web application for OSINT scanning
"""
import os
import sys
import json
import uuid
import threading
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, session
from flask_cors import CORS
import warnings

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from osint_tool.utils.config_loader import ConfigLoader
from osint_tool.utils.logger import Logger
from osint_tool.utils.report_generator import ReportGenerator
from osint_tool.modules.dns_recon import DNSRecon
from osint_tool.modules.whois_lookup import WhoisLookup
from osint_tool.modules.subdomain_enum import SubdomainEnum
from osint_tool.modules.port_scanner import PortScanner
from osint_tool.modules.web_analyzer import WebAnalyzer
from osint_tool.modules.api_integrations import APIIntegrations

app = Flask(__name__,
           template_folder='web/templates',
           static_folder='web/static')
app.secret_key = os.urandom(24)
CORS(app)

# Global storage for scan results and status
scans = {}
scan_lock = threading.Lock()


class WebLogger:
    """Custom logger for web interface"""

    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.logs = []

    def _log(self, level, message):
        """Add log entry"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = {
            'timestamp': timestamp,
            'level': level,
            'message': message
        }
        self.logs.append(log_entry)

        # Update scan status
        with scan_lock:
            if self.scan_id in scans:
                scans[self.scan_id]['logs'] = self.logs

    def info(self, message):
        self._log('info', message)

    def success(self, message):
        self._log('success', message)

    def warning(self, message):
        self._log('warning', message)

    def error(self, message):
        self._log('error', message)

    def debug(self, message):
        self._log('debug', message)

    def section(self, message):
        self._log('section', message)

    def banner(self, message):
        self._log('banner', message)

    def result(self, key, value):
        self._log('result', f"{key}: {value}")

    def list_item(self, item, prefix="  •"):
        self._log('list', f"{prefix} {item}")

    def critical(self, message):
        self._log('critical', message)


def run_scan(scan_id, target, config_dict):
    """Run OSINT scan in background thread"""

    try:
        # Update status
        with scan_lock:
            scans[scan_id]['status'] = 'running'
            scans[scan_id]['started_at'] = datetime.now().isoformat()

        # Create logger
        logger = WebLogger(scan_id)

        # Load config
        config = ConfigLoader()

        # Apply custom config
        if config_dict:
            for key, value in config_dict.items():
                if key in ['dns_enumeration', 'whois_lookup', 'subdomain_enumeration',
                          'port_scanning', 'web_technology_detection']:
                    config.config['modules'][key] = value

        # Initialize modules
        dns_recon = DNSRecon(config, logger)
        whois_lookup = WhoisLookup(config, logger)
        subdomain_enum = SubdomainEnum(config, logger)
        port_scanner = PortScanner(config, logger)
        web_analyzer = WebAnalyzer(config, logger)
        api = APIIntegrations(config, logger)

        results = {}

        # DNS Reconnaissance
        if config_dict.get('dns_enumeration', True):
            try:
                logger.section("DNS Reconnaissance")
                results['dns'] = dns_recon.full_dns_recon(target)
                with scan_lock:
                    scans[scan_id]['progress'] = 20
            except Exception as e:
                logger.error(f"DNS reconnaissance failed: {e}")
                results['dns'] = {'error': str(e)}

        # WHOIS Lookup
        if config_dict.get('whois_lookup', True):
            try:
                logger.section("WHOIS Lookup")
                results['whois'] = whois_lookup.full_whois_lookup(target)
                with scan_lock:
                    scans[scan_id]['progress'] = 40
            except Exception as e:
                logger.error(f"WHOIS lookup failed: {e}")
                results['whois'] = {'error': str(e)}

        # Subdomain Enumeration
        if config_dict.get('subdomain_enumeration', True):
            try:
                logger.section("Subdomain Enumeration")
                results['subdomains'] = subdomain_enum.full_subdomain_enumeration(target)
                with scan_lock:
                    scans[scan_id]['progress'] = 60
            except Exception as e:
                logger.error(f"Subdomain enumeration failed: {e}")
                results['subdomains'] = {'error': str(e)}

        # Port Scanning
        if config_dict.get('port_scanning', True):
            try:
                logger.section("Port Scanning")
                results['ports'] = port_scanner.full_port_scan(target, scan_type='common')
                with scan_lock:
                    scans[scan_id]['progress'] = 80
            except Exception as e:
                logger.error(f"Port scanning failed: {e}")
                results['ports'] = {'error': str(e)}

        # Web Analysis
        if config_dict.get('web_technology_detection', True):
            try:
                logger.section("Web Application Analysis")
                results['web'] = web_analyzer.full_web_analysis(target)
                with scan_lock:
                    scans[scan_id]['progress'] = 90
            except Exception as e:
                logger.error(f"Web analysis failed: {e}")
                results['web'] = {'error': str(e)}

        # External APIs
        if config.get('external_apis.enabled', False):
            results['api'] = {}

            if config.is_api_enabled('shodan'):
                try:
                    logger.info("Querying Shodan...")
                    results['api']['shodan'] = api.shodan_lookup(target)
                except Exception as e:
                    logger.error(f"Shodan query failed: {e}")

            if config.is_api_enabled('virustotal'):
                try:
                    logger.info("Querying VirusTotal...")
                    from osint_tool.utils.helpers import is_valid_ip
                    target_type = 'ip' if is_valid_ip(target) else 'domain'
                    results['api']['virustotal'] = api.virustotal_lookup(target, target_type)
                except Exception as e:
                    logger.error(f"VirusTotal query failed: {e}")

        # Save results
        report_gen = ReportGenerator(config, logger)
        report_paths = report_gen.generate_reports(results, target, formats=['json', 'html'])

        # Update scan with results
        with scan_lock:
            scans[scan_id]['status'] = 'completed'
            scans[scan_id]['results'] = results
            scans[scan_id]['report_paths'] = report_paths
            scans[scan_id]['progress'] = 100
            scans[scan_id]['completed_at'] = datetime.now().isoformat()

        logger.success("Scan completed successfully!")

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        with scan_lock:
            scans[scan_id]['status'] = 'failed'
            scans[scan_id]['error'] = str(e)
            scans[scan_id]['completed_at'] = datetime.now().isoformat()


@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a new OSINT scan"""
    data = request.json
    target = data.get('target')

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    # Generate scan ID
    scan_id = str(uuid.uuid4())

    # Get scan configuration
    config = {
        'dns_enumeration': data.get('dns_enumeration', True),
        'whois_lookup': data.get('whois_lookup', True),
        'subdomain_enumeration': data.get('subdomain_enumeration', True),
        'port_scanning': data.get('port_scanning', True),
        'web_technology_detection': data.get('web_technology_detection', True),
    }

    # Initialize scan
    with scan_lock:
        scans[scan_id] = {
            'id': scan_id,
            'target': target,
            'status': 'initializing',
            'progress': 0,
            'logs': [],
            'results': None,
            'created_at': datetime.now().isoformat(),
            'started_at': None,
            'completed_at': None,
            'config': config
        }

    # Start scan in background thread
    thread = threading.Thread(target=run_scan, args=(scan_id, target, config))
    thread.daemon = True
    thread.start()

    return jsonify({
        'scan_id': scan_id,
        'message': 'Scan started successfully'
    })


@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status"""
    with scan_lock:
        if scan_id not in scans:
            return jsonify({'error': 'Scan not found'}), 404

        scan = scans[scan_id].copy()

        # Don't send full results in status update
        if scan.get('results'):
            scan['has_results'] = True
            scan.pop('results', None)

        return jsonify(scan)


@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get full scan results"""
    with scan_lock:
        if scan_id not in scans:
            return jsonify({'error': 'Scan not found'}), 404

        scan = scans[scan_id]

        if scan['status'] != 'completed':
            return jsonify({'error': 'Scan not completed yet'}), 400

        return jsonify({
            'scan_id': scan_id,
            'target': scan['target'],
            'results': scan['results'],
            'report_paths': scan.get('report_paths', {})
        })


@app.route('/api/scan/<scan_id>/download/<format>')
def download_report(scan_id, format):
    """Download scan report"""
    with scan_lock:
        if scan_id not in scans:
            return jsonify({'error': 'Scan not found'}), 404

        scan = scans[scan_id]
        report_paths = scan.get('report_paths', {})

        if format not in report_paths:
            return jsonify({'error': f'Report format {format} not found'}), 404

        filepath = report_paths[format]

        if not os.path.exists(filepath):
            return jsonify({'error': 'Report file not found'}), 404

        return send_file(
            filepath,
            as_attachment=True,
            download_name=os.path.basename(filepath)
        )


@app.route('/api/scans', methods=['GET'])
def list_scans():
    """List all scans"""
    with scan_lock:
        scan_list = []
        for scan_id, scan in scans.items():
            scan_list.append({
                'id': scan['id'],
                'target': scan['target'],
                'status': scan['status'],
                'progress': scan['progress'],
                'created_at': scan['created_at'],
                'completed_at': scan.get('completed_at')
            })

        # Sort by created_at descending
        scan_list.sort(key=lambda x: x['created_at'], reverse=True)

        return jsonify(scan_list)


@app.route('/api/scan/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a scan"""
    with scan_lock:
        if scan_id not in scans:
            return jsonify({'error': 'Scan not found'}), 404

        # Delete report files
        scan = scans[scan_id]
        report_paths = scan.get('report_paths', {})
        for filepath in report_paths.values():
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except:
                pass

        del scans[scan_id]

        return jsonify({'message': 'Scan deleted successfully'})


@app.route('/results/<scan_id>')
def view_results(scan_id):
    """View scan results page"""
    return render_template('results.html', scan_id=scan_id)


@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current configuration"""
    config = ConfigLoader()

    return jsonify({
        'modules': config.get('modules', {}),
        'external_apis': {
            'enabled': config.get('external_apis.enabled', False),
            'shodan_enabled': config.is_api_enabled('shodan'),
            'virustotal_enabled': config.is_api_enabled('virustotal'),
        },
        'limits': config.get('limits', {})
    })


if __name__ == '__main__':
    print("""
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║         OSINT Collection Tool - Web Interface             ║
║                                                           ║
║  Access the web interface at:                             ║
║  http://localhost:5000                                    ║
║                                                           ║
║  Press Ctrl+C to stop the server                          ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """)

    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
