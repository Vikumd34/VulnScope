class ServiceDetector:

    def __init__(self):

        self.services = {

            20: "FTP Data",
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            8080: "HTTP Alternate"

        }

    def get_service(self, port):

        return self.services.get(port, "Unknown")