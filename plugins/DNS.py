from nfstream import NFPlugin
import dpkt

class AuxDNSFeatures(NFPlugin):
    """
    This pluguin extracts DNS flow features

    Attributes
    ----------
    flow.udps.dns_query_id: %DNS_QUERY_ID DNS query transaction Id
    flow.udps.dns_query_type: %DNS_QUERY_TYPE  DNS query type (e.g. 1=A, 2=NS..) 
    flow.udps.dns_ttl_answer: %DNS_TTL_ANSWER  TTL of the first A record (if any)

    """

    def on_init(self, packet, flow):
        flow.udps.dns_query_id = 0
        flow.udps.dns_query_type = 0
        flow.udps.dns_ttl_answer = 0

    def on_update(self, packet, flow):
        try:
            ip = dpkt.ip.IP(packet.ip_packet)
            udp = ip.data
            dns = dpkt.dns.DNS(udp.data)
            flow.udps.dns_query_id = int(dns.id)
            flow.udps.dns_query_type = int(dns.qd[0].type)
            if len(dns.an) >= 1:
                flow.udps.dns_ttl_answer = int(dns.an[0].ttl)
        except: 
            pass
        
        
