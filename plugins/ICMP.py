from nfstream import NFPlugin
import dpkt

class AuxICMPFeatures(NFPlugin):
    """
    This pluguin extracts ICMP flow features

    Attributes
    ----------
    flow.udps.icmp_type: %ICMP_TYPE ICMP Type * 256 + ICMP code
    flow.udps.icmp_v4_type:%ICMP_IPV4_TYPE  ICMP Type

    """

    def on_init(self, packet, flow):
        flow.udps.icmp_type = 0
        flow.udps.icmp_v4_type = 0
        
        try:
            if packet.ip_version == 4:
                decoded_packet = dpkt.icmp.ICMP(packet.ip_packet)
                flow.udps.icmp_v4_type = decoded_packet.type
                flow.udps.icmp_type = decoded_packet.type * 256 + decoded_packet.code
            elif packet.ip_version == 6:
                decoded_packet = dpkt.icmp6.ICMP6(packet.ip_packet)
                flow.udps.icmp_type = decoded_packet.type * 256 + decoded_packet.code
        except:
            pass

    def on_update(self, packet, flow):
        try:
            if packet.ip_version == 4:
                decoded_packet = dpkt.icmp.ICMP(packet.ip_packet)
                flow.udps.icmp_v4_type = int(decoded_packet.type)
                flow.udps.icmp_type = int(decoded_packet.type) * 256 + int(decoded_packet.code)
            elif packet.ip_version == 6:
                decoded_packet = dpkt.icmp6.ICMP6(packet.ip_packet)
                flow.udps.icmp_type = int(decoded_packet.type) * 256 + int(decoded_packet.code)
        except:
            pass
