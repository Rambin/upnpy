import socket
import select
from datetime import datetime, timedelta
from upnpy.ssdp.SSDPHeader import SSDPHeader
from upnpy.ssdp.SSDPDevice import SSDPDevice


class SSDPRequest(SSDPHeader):

    """
        **Create and perform an SSDP request**

        :param method: SSDP request method [M-SEARCH or NOTIFY]
    """

    def __init__(self, ssdp_mcast_addr='239.255.255.250', ssdp_port=1900, **headers):
        super().__init__(**headers)

        self.SSDP_MCAST_ADDR = ssdp_mcast_addr
        self.SSDP_PORT = ssdp_port

        self.set_header('HOST', f'{self.SSDP_MCAST_ADDR}:{self.SSDP_PORT}')

    def m_search(self, discover_delay=2, st='ssdp:all', **headers):

        """
            **Perform an M-SEARCH SSDP request**

            Send an SSDP M-SEARCH request for finding UPnP devices on the network.

            :param discover_delay: Device discovery delay in seconds
            :type discover_delay: int
            :param st: Specify device Search Target
            :type st: str
            :param headers: Specify M-SEARCH specific headers
            :type headers: str
            :return: List of device that replied
            :rtype: list
        """

        self.set_method('M-SEARCH')

        self.set_header('MAN', '"ssdp:discover"')
        self.set_header('MX', discover_delay)
        self.set_header('ST', st)
        self.set_headers(**headers)

        devices = self._send_request(self._get_raw_request(), discover_delay=discover_delay)

        for device in devices:
            yield device

    def notify(self, **headers):

        """
        Perform a NOTIFY SSDP request

        :param headers: Specify NOTIFY specific headers
        :return:
        """
        self.set_method('NOTIFY')
        self.set_headers(**headers)

    def _get_raw_request(self):

        """
        Get raw request data to send to server
        """

        final_request_data = ''

        if self.method is not None:
            ssdp_start_line = f'{self.method} * HTTP/1.1'
        else:
            ssdp_start_line = 'HTTP/1.1 200 OK'

        final_request_data += f'{ssdp_start_line}\r\n'

        for header, value in self.headers.items():
            final_request_data += f'{header}: {value}\r\n'

        final_request_data += '\r\n'

        return final_request_data

    def _send_request(self, message, discover_delay):
        req = message.encode()
        SSDP_TARGET = (self.SSDP_MCAST_ADDR, self.SSDP_PORT)
        ddl = datetime.now() + timedelta(seconds=discover_delay)
        
        sockets = []
        addrs = set()
        
        for addr in socket.gethostbyname_ex(socket.gethostname())[2]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, discover_delay)
                sock.bind((addr, 0))
                sockets.append(sock)
            except socket.error:
                pass
        
        for sock in [s for s in sockets]:
            try:
                sock.sendto(req, SSDP_TARGET)
                sock.setblocking(False)
            except socket.error:
                sockets.remove(sock)
                sock.close()
        
        devices = []
        
        try:
            while sockets:
                life = (ddl - datetime.now()).total_seconds()
                if life <= 0:
                    break
                
                ready = select.select(sockets, [], [], life)[0]
                
                for sock in ready:
                    try:
                        response, addr = sock.recvfrom(65507)
                        if not addr in addrs:
                            addrs.add(addr)
                            devices.append(SSDPDevice(addr, response.decode(), sock.getsockname()[0]))
                    except UnicodeDecodeError:
                        continue
                    except socket.error:
                        sockets.remove(sock)
                        sock.close()
                        continue
                        
        finally:
            for s in sockets:
                s.close()
        
        return devices
