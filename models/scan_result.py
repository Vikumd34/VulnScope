from datetime import datetime

class ScanResult:
    def __init__(self):
        self.target = ""
        self.host_info = {}
        self.dns = {}
        self.whois = {}
        self.open_ports = []
        self.scan_time = None
        self.job = None
        self.error = None
