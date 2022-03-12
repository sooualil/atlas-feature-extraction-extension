from nfstream import NFPlugin
import dpkt
from scapy.all import  IP, IPv6, TCP


class AuxTCPWindowMinMAx(NFPlugin):
    """
    This pluguin extracts TCP window flow features

    Attributes
    ----------
    flow.udps.tcp_win_max_in: %TCP_WIN_MAX_IN  Max TCP Window (src->dst)
    flow.udps.tcp_win_max_out: %TCP_WIN_MIN_OUT Min TCP Window (dst->src)
    """
    def __init__(self):
        super(AuxTCPWindowMinMAx, self).__init__()

    def on_init(self, packet, flow):
        
        flow.udps.tcp_win_max_in = 0
        flow.udps.tcp_win_max_out = 0
        try:
            if packet.ip_version == 4:
                s_packet = IP(packet.ip_packet)
            elif packet.ip_version == 6:
                s_packet = IPv6(packet.ip_packet)


            if s_packet.haslayer(TCP):
                flow.udps.tcp_win_max_in = s_packet[TCP].window
                flow.udps.tcp_win_max_out = s_packet[TCP].window  
        except:
            pass

    def on_update(self, packet, flow):
        try:
            if packet.ip_version == 4:
                s_packet = IP(packet.ip_packet)
            elif packet.ip_version == 6:
                s_packet = IPv6(packet.ip_packet)

            if s_packet.haslayer(TCP):
                win = s_packet[TCP].window
                if packet.direction == 0 and win > flow.udps.tcp_win_max_in and packet.protocol == 6 :
                    flow.udps.tcp_win_max_in = win
                elif packet.direction == 1 and win > flow.udps.tcp_win_max_out and packet.protocol == 6:
                    flow.udps.tcp_win_max_out = win
        except:
            pass

class AuxTCPFlagsFeatures(NFPlugin): 
    """
    This pluguin extracts TCP flags flow features

    Attributes
    ----------
    flow.udps.src2dst_flags:  %CLIENT_TCP_FLAGS Cumulative of all client TCP flags
    flow.udps.dst2src_flags: %SERVER_TCP_FLAGS  Cumulative of all server TCP flags
    flow.udps.tcp_flags: %TCP_FLAGS Cumulative of all flow TCP flags
    """
    def __init__(self):
        super(AuxTCPFlagsFeatures, self).__init__()

    def get_flags(self, flag):
        flag = int(flag)
        di = {'urg': 32, 'ack': 16, 'psh': 8, 'rst': 4, 'syn': 2, 'fin': 1}
        flags = [k for k, v in di.items() if v & flag]
        return set(flags)
    
    def get_cumul(self, l):
        di = {'urg': 32, 'ack': 16, 'psh': 8, 'rst': 4, 'syn': 2, 'fin': 1}
        cumul = 0
        for i in l:
            cumul += di[i]
        return cumul

    def on_init(self, packet, flow):
        curr_flag = 0
        self.bi_flags = set()
        self.s2d_flags = set()
        self.d2s_flags = set()
        
        flow.udps.src2dst_flags = 0
        flow.udps.dst2src_flags = 0
        flow.udps.tcp_flags = 0 
        try:
            if packet.ip_version == 4 and packet.protocol == 6:
                decoded_packet = dpkt.ip.IP(packet.ip_packet)
                curr_flag = decoded_packet.data.flags
                
            elif packet.ip_version == 6 and packet.protocol == 6:
                decoded_packet = dpkt.ip6.IP6(packet.ip_packet)
                curr_flag = decoded_packet.data.flags
            
            if curr_flag != 0:
                cur_s = self.get_flags(curr_flag)
                self.bi_flags = self.bi_flags.union(cur_s)
            if packet.direction == 0 and curr_flag != 0:
                cur_s = self.get_flags(curr_flag)
                self.s2d_flags = self.s2d_flags.union(cur_s)
            elif packet.direction == 1 and curr_flag != 0:
                cur_s = self.get_flags(curr_flag)
                self.d2s_flags = self.d2s_flags.union(cur_s)
        except:
            pass


    def on_update(self, packet, flow):
        curr_flag = 0
        try:
            if packet.ip_version == 4 and packet.protocol == 6:
                decoded_packet = dpkt.ip.IP(packet.ip_packet)
                curr_flag = decoded_packet.data.flags
    
            if packet.ip_version == 4 and packet.protocol == 6:
                decoded_packet = dpkt.ip.IP(packet.ip_packet)
                curr_flag = decoded_packet.data.flags
                
            elif packet.ip_version == 6 and packet.protocol == 6:
                decoded_packet = dpkt.ip6.IP6(packet.ip_packet)
                curr_flag = decoded_packet.data.flags
            
            if curr_flag != 0:
                cur_s = self.get_flags(curr_flag)
                self.bi_flags = self.bi_flags.union(cur_s)
            if packet.direction == 0 and curr_flag != 0:
                cur_s = self.get_flags(curr_flag)
                self.s2d_flags = self.s2d_flags.union(cur_s)
            elif packet.direction == 1 and curr_flag != 0:
                cur_s = self.get_flags(curr_flag)
                self.d2s_flags = self.d2s_flags.union(cur_s)
                
            flow.udps.tcp_flags = self.get_cumul(self.bi_flags)
            flow.udps.src2dst_flags = self.get_cumul(self.s2d_flags)
            flow.udps.dst2src_flags = self.get_cumul(self.d2s_flags)
        except:
            pass
            
    def on_expire(self, flow):
        try:
            flow.udps.tcp_flags = self.get_cumul(self.bi_flags)
            flow.udps.src2dst_flags = self.get_cumul(self.s2d_flags)
            flow.udps.dst2src_flags = self.get_cumul(self.d2s_flags)
        except:
            pass

class AuxPktRetransmissionFeatures(NFPlugin):
    """
    This pluguin extracts TCP retransmission flow features

    Attributes
    ----------
    flow.udps.retransmitted_in_packets:  %RETRANSMITTED_IN_PKTS Number of retransmitted TCP flow packets (src->dst)
    flow.udps.retransmitted_out_packets: %RETRANSMITTED_OUT_PKTS Number of retransmitted TCP flow packets (dst->src)
    flow.udps.retransmitted_in_bytes: %RETRANSMITTED_IN_BYTES Number of retransmitted TCP flow bytes (src->dst)
    flow.udps.retransmitted_out_bytes: %RETRANSMITTED_OUT_BYTES Number of retransmitted TCP flow bytes (dst->src)
    """
    def on_init(self, packet, flow):
        self.d2s = set()
        self.s2d = set()
        self.d2s_load = set()
        self.s2d_load = set()
        flow.udps.retransmitted_in_packets = 0
        flow.udps.retransmitted_out_packets = 0
        flow.udps.retransmitted_in_bytes = 0
        flow.udps.retransmitted_out_bytes = 0
        try:
            if packet.protocol == 6:
                s_packet = IP(packet.ip_packet)
                if not (hasattr(s_packet.getlayer(1), 'seq') and  hasattr(s_packet.getlayer(1), 'load')):
                    return
                seq = s_packet.getlayer(1).seq
                load = s_packet.getlayer(1).load
                if packet.direction == 0 and len(load) > 0:
                    self.s2d.add(seq)
                    self.s2d_load.add(load)
                elif packet.direction == 1 and len(load) > 0:
                    self.d2s.add(seq)
                    self.d2s.add(load)
        except:
            pass
    def on_update(self, packet, flow):
        try:
            if packet.protocol == 6:
                s_packet = IP(packet.ip_packet)
                if not (hasattr(s_packet.getlayer(1), 'seq') and  hasattr(s_packet.getlayer(1), 'load')):
                    return
                seq = s_packet.getlayer(1).seq
                load = s_packet.getlayer(1).load
                if packet.direction == 0:
                    if len ({seq} - self.s2d) != 0 and len({load} - self.d2s_load) != 0 and len(load) > 0:
                        self.s2d.add(seq)
                        self.s2d_load.add(load)
                    else:
                        flow.udps.retransmitted_in_bytes += packet.ip_size 
                        flow.udps.retransmitted_in_packets += 1

                elif packet.direction == 1:
                    if len (set([seq]) - self.d2s) != 0 and len({load} - self.d2s_load) != 0 and len(load) > 0:
                        self.d2s.add(seq)
                        self.d2s_load.add(load)
                    else:
                        flow.udps.retransmitted_out_bytes += packet.ip_size 
                        flow.udps.retransmitted_out_packets += 1
        except:
            pass
