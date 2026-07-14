from scanner.port_scanner import PortScanner
from scanner.service_detector import ServiceDetector

class ScannerEngine:

    def __init__(self):
        self.version = "1.0"
        self.name = "VulnScope Scanner Engine"
        self.port_scanner = PortScanner()
        self.service_detector = ServiceDetector()

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

    def print_scan_results(self, target, results):
        print("\n========== Scan Results ==========")
        print(f"Target: {target}")

        if results:
            for port in results:
                print(f"[OPEN] Port {port}")
        else:
            print("No open ports found.")

        print("==================================")