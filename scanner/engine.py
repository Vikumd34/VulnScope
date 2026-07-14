from scanner.port_scanner import PortScanner
from scanner.service_detector import ServiceDetector
from scanner.host_info import HostInfo
from database.scan_manager import ScanManager

class ScannerEngine:

    def __init__(self):
        self.version = "1.0"
        self.name = "VulnScope Scanner Engine"
        self.port_scanner = PortScanner()
        self.service_detector = ServiceDetector()
        self.host_info = HostInfo()
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