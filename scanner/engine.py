from scanner.port_scanner import PortScanner

class ScannerEngine:

    def __init__(self):
        self.version = "1.0"
        self.name = "VulnScope Scanner Engine"
        self.port_scanner = PortScanner()

        print(f"{self.name} Started")

    def get_version(self):
        return self.version

    def port_scan(self, target):
        return self.port_scanner.scan(target)

    def print_scan_results(self, target, results):
        print("\n========== Scan Results ==========")
        print(f"Target: {target}")

        if results:
            for port in results:
                print(f"[OPEN] Port {port}")
        else:
            print("No open ports found.")

        print("==================================")