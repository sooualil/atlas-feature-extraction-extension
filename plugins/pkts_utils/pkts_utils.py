import binascii
import numpy as np
import copy
from scapy.all import TCP, UDP, IP, IPv6, ARP, raw


def get_packet_matrix(packet):
    """
    Transform a packet content into 1D array of bytes

    Parameters
    ----------
    packet : an IP packet

    Returns
    -------
    1D ndarry of packet bytes
    """
    hexst = binascii.hexlify(raw(packet))  
    fh = np.array([int(hexst[i:i+2],16) for i in range(0, len(hexst), 2)])   
    fh = np.uint8(fh)
    return fh.reshape(-1)


def santize_packet_zeros(packet):
    """
    This method sanitize a packet by annonymizing IP and MAC adresses

    Parameters
    ----------
    packet : a packet

        Returns
    -------
    sanitized packet
    """
    pkt = copy.deepcopy(packet)
    ipv4='0.0.0.0'
    ipv6='0000:00::00'
    mac='00:00:00:00:00:00'
    
    if pkt.haslayer(IPv6):
        pkt[IPv6].src = ipv6
        pkt[IPv6].dst = ipv6
        if pkt.haslayer(TCP):
            pkt[TCP].sport = 0
            pkt[TCP].dport = 0
        
        elif pkt.haslayer(UDP):
            pkt[UDP].sport = 0
            pkt[UDP].dport = 0
    elif pkt.haslayer(IP) :
        pkt[IP].src = ipv4
        pkt[IP].dst = ipv4
        if pkt.haslayer(TCP):
            pkt[TCP].sport = 0
            pkt[TCP].dport = 0
        
        elif pkt.haslayer(UDP):
            pkt[UDP].sport = 0
            pkt[UDP].dport = 0
        
    elif pkt.haslayer(ARP):
        pkt[ARP].hwsrc = mac
        pkt[ARP].hwdst = mac
        pkt[ARP].psrc = ipv4
        pkt[ARP].pdst = ipv4
    else:
        pass
    
    return pkt

