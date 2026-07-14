import socket

class PortScanner:

    def __init__(self):
        self.timeout = 1

    def scan_port(self, target, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            result = sock.connect_ex((target, port))

            sock.close()

            return result == 0

        except Exception:
            return False

    def scan(self, target):
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]
        open_ports = []

        for port in ports:
            if self.scan_port(target, port):
                open_ports.append(port)

        return open_ports