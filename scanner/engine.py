class ScannerEngine:

    def __init__(self):
        self.version = "1.0"
        self.name = "VulnScope Scanner Engine"

        print(f"{self.name} Started")

    def get_version(self):
        return self.version