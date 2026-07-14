import ipaddress
import socket


class TargetValidator:

    @staticmethod
    def validate(target):

        if not target or not target.strip():
            return False

        target = target.strip()

        # Check if it's an IP address
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass

        # Check if it's a hostname
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False