import random , configparser
import socket
from scapy.all import *
from scapy.contrib.pfcp import *
from scapy.contrib.gtp import *

LOCAL_DATA_HANDLER = lambda x:x
REMOTE_DATA_HANDLER = lambda x:x

BUFFER_SIZE = 2 ** 15

gtpu_config = configparser.ConfigParser()
gtpu_config.read('config.ini')
proxy_socket2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

gnbport = 0

class Gtpu_proxy:
    def __init__ (self, gtpu_host , total_upf , upfs):
        self.gtpu_host = gtpu_host
        self.total_upf = total_upf
        self.upfs = upfs
        # self.gnbport = 0

    def gtpu_proxy_startup(self):
        global proxy_socket2
        upf_ip = []
        gtpu_port = int(gtpu_config['gtpu']['port'])
        ue_host_ip = gtpu_config['ue']['host_address']
        proxy_socket2.bind(self.ip_to_tuple(self.gtpu_host))
        logging.info('%s %s', '[GTP-U Proxy] The GTP-U Proxy is started on', self.gtpu_host)
        upf_id = random.randint(0,self.total_upf)
        for i in self.upfs:
            upf_ip.append(self.ip_to_tuple(i)[0])

        while True:
            data, address = proxy_socket2.recvfrom(BUFFER_SIZE)
            if address[0] == "10.244.0.17":
                gnbport = address[1]
                try:
                    if GTP_U_Header(data)[TCP]:
                        proxy_socket2.sendto(data,(upf_ip[0], gtpu_port))
                    # els7
                except Exception as e:
                    logging.info('%s %s', "[GTP-U][UDP] Error :", e)
                    logging.info('%s %s', "[GTP-U][UDP] UDP packet dst ip :", GTP_U_Header(data)[IP].dst)
                    upf_id = random.randint(0,1)
                    logging.info('%s %s', "[GTP-U][UDP] swtich to UPF :", upf_id)
                    proxy_socket2.sendto(data,(upf_ip[upf_id],gtpu_port))
            else :
                proxy_socket2.sendto(data,(ue_host_ip, gnbport))

    def ip_to_tuple(self,ip):
        host = ip.split(':')[0]
        port = ip.split(':')[1]
        return (host, int(port))
