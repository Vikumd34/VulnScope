from services.port_scanner import PortScanner
from services.service_detector import ServiceDetector
from services.host_info import HostInfo
from services.dns_scanner import DNSScanner
from services.whois_scanner import WhoisScanner
from services.http_scanner import HTTPScanner
from services.security_headers import SecurityHeaderAnalyzer
from services.ssl_scanner import SSLScanner
from database.scan_manager import ScanManager
from models.scan_result import ScanResult
from utils.validator import TargetValidator
from datetime import datetime

class ScannerEngine:

    def __init__(self):
        self.version = "1.0"
        self.name = "VulnScope Scanner Engine"
        self.port_scanner = PortScanner()
        self.service_detector = ServiceDetector()
        self.host_info = HostInfo()
        self.dns_scanner = DNSScanner()
        self.http_scanner = HTTPScanner()
        self.security_analyzer = SecurityHeaderAnalyzer()
        self.ssl_scanner = SSLScanner()
        self.whois_scanner = WhoisScanner()
        self.scan_manager = ScanManager()

        print(f"{self.name} Started")

    def get_version(self):
        return self.version

    def port_scan(self, target):
        return self.port_scanner.scan(target)

    def detect_services(self, ports):
        results = []

        for port in ports:
            service = self.service_detector.get_service(port)
            results.append({
                "port": port,
                "service": service
            })

        return results

    def create_scan(self, target):
        return self.scan_manager.create_job(target)

    def dns_lookup(self, target):
        try:
            return self.dns_scanner.get_records(target)
        except Exception:
            return {}

    def whois_scan(self, target):
        try:
            return self.whois_scanner.scan(target)
        except Exception:
            return {}

    def run_scan(self, target):
        result = ScanResult()
        result.target = target
        result.scan_time = datetime.now()

        # Validate
        if not TargetValidator.validate(target):
            result.error = "Invalid IP address or hostname."
            return result

        # Create job
        job = self.create_scan(target)
        result.job = job
        job.start()

        # Host info
        result.host_info = self.get_host_info(target)

        # DNS
        result.dns = self.dns_lookup(target)

        # WHOIS
        result.whois = self.whois_scan(target)

        # Port scan
        ports = self.port_scan(target)
        # ports is list of ints; detect services
        result.open_ports = self.detect_services(ports)

        # HTTP scan
        try:
            result.http = self.http_scanner.scan(target)
        except Exception:
            result.http = {}

        # Analyze security headers if available
        try:
            headers = result.http.get('headers') if result.http else {}
            result.security_headers = self.security_analyzer.analyze(headers or {})
        except Exception:
            result.security_headers = {}

        # SSL/TLS scan
        try:
            result.ssl = self.ssl_scanner.scan(target)
        except Exception:
            result.ssl = {}

        job.results = result.open_ports
        job.complete()

        return result

    def get_host_info(self, target):
        return self.host_info.get_host_information(target)

    def print_scan_results(self, target, results):
        print("\n========== Scan Results ==========")
        print(f"Target: {target}")

        if results:
            for port in results:
                print(f"[OPEN] Port {port}")
        else:
            print("No open ports found.")

        print("==================================")