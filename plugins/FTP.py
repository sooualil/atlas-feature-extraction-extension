from nfstream import NFPlugin
from scapy.all import  IP


class AuxFTPFeatures(NFPlugin):
    """
    This pluguin extracts FTP flow features

    Attributes
    ----------
    flow.udps.ftp_command_ret_code: %FTP_COMMAND_RET_CODE FTP client command return code   

    """

    def on_init(self, packet, flow):
        flow.udps.ftp_command_ret_code = 0
        try:
            if packet.protocol == 6 and (packet.dst_port == 21 or packet.src_port == 21) and packet.direction == 1:
                s_packet = IP(packet.ip_packet)
                if hasattr(s_packet.getlayer(2), 'load'):
                    load = s_packet.getlayer(2).load
                    numbs = [int(word) for word in load.split() if word.isdigit()]
                    if len(numbs) > 0 and numbs[0] <= 10068 and numbs[0] >= 100:
                        flow.udps.ftp_command_ret_code = numbs[0]
        except:
            pass
            
        
    def on_update(self, packet, flow):
        try:
            if packet.protocol == 6 and (packet.dst_port == 21 or packet.src_port == 21) and packet.direction == 1:
                s_packet = IP(packet.ip_packet )
                if hasattr(s_packet.getlayer(2), 'load'):
                    load = s_packet.getlayer(2).load
                    numbs = [int(word) for word in load.split() if word.isdigit()]
                    if len(numbs) > 0 and numbs[0] <= 10068 and numbs[0] >= 100:
                        flow.udps.ftp_command_ret_code = numbs[0]
        except:
            pass
