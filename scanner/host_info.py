import socket

class HostInfo:

    def get_host_information(self, target):

        info = {}

        try:
            ip = socket.gethostbyname(target)

            info["target"] = target
            info["ip"] = ip

            hostname = socket.getfqdn(target)
            info["hostname"] = hostname

            return info

        except Exception:
            return None
