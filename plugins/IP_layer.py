from nfstream import NFPlugin
from scapy.all import  IP, IPv6
from .pkts_utils.pkts_utils import santize_packet_zeros, get_packet_matrix
import numpy as np

class AuxPktMinMaxSizeFeatures(NFPlugin):
    """
    This pluguin extracts IP packets flow features

    Attributes
    ----------
    flow.udps.min_ttl: %MIN_TTL  Min flow TTL
    flow.udps.max_ttl: %MAX_TTL  Max flow TTL
    flow.udps.min_ip_pkt_len: %MIN_IP_PKT_LEN Len of the smallest flow IP packet observed
    flow.udps.max_ip_pkt_len: %MAX_IP_PKT_LEN Len of the largest flow IP packet observed

    """

    def on_init(self, packet, flow):
        flow.udps.min_ttl = 100000
        flow.udps.max_ttl = -100000
        flow.udps.min_ip_pkt_len = 100000
        flow.udps.max_ip_pkt_len = -100000

        if packet.ip_version == 4:
            decoded_packet = IP(packet.ip_packet)
            lenght = decoded_packet.len
            try:
                ttl = decoded_packet.ttl
            except:
                ttl = 0

        elif packet.ip_version == 6:
            decoded_packet = IPv6(packet.ip_packet)
            lenght = decoded_packet.plen
            try:
                ttl = decoded_packet.ttl
            except:
                ttl = 0

        flow.udps.min_ip_pkt_len = lenght
        flow.udps.max_ip_pkt_len = lenght
        
        
        flow.udps.min_ttl = ttl
        flow.udps.max_ttl = ttl
        
            

    def on_update(self, packet, flow):
        
        if packet.ip_version == 4:
            decoded_packet = IP(packet.ip_packet)
            lenght = decoded_packet.len
            try:
                ttl = decoded_packet.ttl
            except:
                ttl = 0

        elif packet.ip_version == 6:
            decoded_packet = IPv6(packet.ip_packet)
            lenght = decoded_packet.plen
            try:
                ttl = decoded_packet.ttl
            except:
                ttl = 0
            
        if ttl < flow.udps.min_ttl:
            flow.udps.min_ttl = ttl
        elif ttl > flow.udps.max_ttl:
            flow.udps.max_ttl = ttl
        
        if lenght < flow.udps.min_ip_pkt_len:
            flow.udps.min_ip_pkt_len = lenght
        elif lenght > flow.udps.max_ip_pkt_len:
            flow.udps.max_ip_pkt_len = lenght


class AuxRawIPPkt(NFPlugin):
    """
    This pluguin extracts bidirectional flow IP packets bytes

    Attributes
    ----------
    flow.udps.bidirectional_pkts: a dictionnary of packets bytes orderd by their arrival time

    """

    def on_init(self, packet, flow):
        flow.udps.bidirectional_pkts = {}
        self.k = 1
        try:
            if packet.ip_version == 4:
                decoded_packet = IP(packet.ip_packet)

            elif packet.ip_version == 6:
                decoded_packet = IPv6(packet.ip_packet)


            san_pkt = santize_packet_zeros(decoded_packet)

            raw_matrix = get_packet_matrix(san_pkt)

            flow.udps.bidirectional_pkts[str(self.k)] = raw_matrix
        except:
            pass
            #self.k = self.k + 1
            #flow.udps.bidirectional_pkts[str(self.k)] = np.zeros(20)


    def on_update(self, packet, flow):
        load = None
        try:
            if packet.ip_version == 4:
                decoded_packet = IP(packet.ip_packet)

            elif packet.ip_version == 6:
                decoded_packet = IPv6(packet.ip_packet)

            san_pkt = santize_packet_zeros(decoded_packet)
            raw_matrix = get_packet_matrix(san_pkt)

            self.k = self.k + 1
            flow.udps.bidirectional_pkts[str(self.k)] = raw_matrix
        except:
            pass
            #self.k = self.k + 1
            #flow.udps.bidirectional_pkts[str(self.k)] = np.zeros(20)

        
class AuxRawIPPktdirections(NFPlugin):
    """
    This pluguin extracts flow IP packets bytes of each direction

    Attributes
    ----------
    flow.udps.src2dst_pkts: a dictionnary of SRC --> DST packets bytes orderd by their arrival time
    flow.udps.dst2src_pkts: a dictionnary of DST --> SRC packets bytes orderd by their arrival time

    """
    def on_init(self, packet, flow):
        flow.udps.src2dst_pkts = {}
        flow.udps.dst2src_pkts = {}
        self.k = 1
        try:
            if packet.ip_version == 4:
                decoded_packet = IP(packet.ip_packet)

            elif packet.ip_version == 6:
                decoded_packet = IPv6(packet.ip_packet)

            san_pkt = santize_packet_zeros(decoded_packet)

            raw_matrix = get_packet_matrix(san_pkt)

            if packet.direction == 0:
                flow.udps.src2dst_pkts[str(self.k)] = raw_matrix
            elif packet.direction == 1:
                flow.udps.dst2src_pkts[str(self.k)] = raw_matrix  
        except:
            pass

    def on_update(self, packet, flow):
        try:
            if packet.ip_version == 4:
                decoded_packet = IP(packet.ip_packet)

            elif packet.ip_version == 6:
                decoded_packet = IPv6(packet.ip_packet)

            san_pkt = santize_packet_zeros(decoded_packet)       
            raw_matrix = get_packet_matrix(san_pkt)
            self.k = self.k + 1
            if packet.direction == 0:
                flow.udps.src2dst_pkts[str(self.k)] = raw_matrix
            elif packet.direction == 1:
                flow.udps.dst2src_pkts[str(self.k)] = raw_matrix 
        except:
            pass
