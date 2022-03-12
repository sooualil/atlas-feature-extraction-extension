from nfstream import NFPlugin
import math

class AuxPktSizeFeatures(NFPlugin):
    """
    This pluguin counts the number of packet per size interval

    Attributes
    ----------
    flow.udps.num_pkts_up_to_128_bytes: %NUM_PKTS_UP_TO_128_BYTES number of packet having less than 128 bytes
    flow.udps.num_pkts_128_to_256_bytes: %NUM_PKTS_128_TO_256_BYTES number of packet having size between  128 and 256 bytes
    flow.udps.num_pkts_256_to_512_bytes: %NUM_PKTS_256_TO_512_BYTES number of packet having size between  256 and 512 bytes
    flow.udps.num_pkts_512_to_1024_bytes: %NUM_PKTS_512_TO_1024_BYTES number of packet having size between  512 and 1024 bytes
    flow.udps.num_pkts_1024_to_1514_bytes: %NUM_PKTS_1024_TO_1514_BYTES number of packet having size greater than 1024 bytes
    """

    def on_init(self, packet, flow):
        flow.udps.num_pkts_up_to_128_bytes = 0
        flow.udps.num_pkts_128_to_256_bytes = 0
        flow.udps.num_pkts_256_to_512_bytes = 0
        flow.udps.num_pkts_512_to_1024_bytes = 0
        flow.udps.num_pkts_1024_to_1514_bytes = 0
        if packet.ip_size <= 128:
            flow.udps.num_pkts_up_to_128_bytes += 1
        elif packet.ip_size > 128 and packet.ip_size <= 256:
            flow.udps.num_pkts_128_to_256_bytes += 1
        elif packet.ip_size > 256 and packet.ip_size <= 512:
            flow.udps.num_pkts_256_to_512_bytes += 1
        elif packet.ip_size > 512 and packet.ip_size <= 1024:
            flow.udps.num_pkts_512_to_1024_bytes += 1
        elif packet.ip_size > 1024 and packet.ip_size <= 1514:
            flow.udps.num_pkts_1024_to_1514_bytes += 1

    def on_update(self, packet, flow):
        if packet.ip_size <= 128:
            flow.udps.num_pkts_up_to_128_bytes += 1
        elif packet.ip_size > 128 and packet.ip_size <= 256:
            flow.udps.num_pkts_128_to_256_bytes += 1
        elif packet.ip_size > 256 and packet.ip_size <= 512:
            flow.udps.num_pkts_256_to_512_bytes += 1
        elif packet.ip_size > 512 and packet.ip_size <= 1024:
            flow.udps.num_pkts_512_to_1024_bytes += 1
        elif packet.ip_size > 1024 and packet.ip_size <= 1514:
            flow.udps.num_pkts_1024_to_1514_bytes += 1


class AuxSecBytesFeatures(NFPlugin):
    """
    This pluguin computes second_bytes and throughput for each direction

    Attributes
    ----------
    flow.udps.src_to_dst_second_bytes: %SRC_TO_DST_SECOND_BYTES        Bytes/sec (src->dst)
    flow.udps.dst_to_src_second_bytes: %DST_TO_SRC_SECOND_BYTES        Bytes/sec2 (dst->src)
    flow.udps.src_to_dst_avg_throughput: %SRC_TO_DST_AVG_THROUGHPUT       Src to dst average thpt (bps)
    flow.udps.dst_to_src_avg_throughput: %DST_TO_SRC_AVG_THROUGHPUT       Dst to src average thpt (bps)
    flow.udps.src_to_dst_second_bytes2: %SRC_TO_DST_SECOND_BYTES        Bytes/sec (src->dst)
    flow.udps.dst_to_src_second_bytes2: %DST_TO_SRC_SECOND_BYTES        Bytes/sec2 (dst->src)
    flow.udps.src_to_dst_avg_throughput2: %SRC_TO_DST_AVG_THROUGHPUT       Src to dst average thpt (bps)
    flow.udps.dst_to_src_avg_throughput2: %DST_TO_SRC_AVG_THROUGHPUT       Dst to src average thpt (bps)
    """

    def on_init(self, packet, flow):
        self.dic_src2dst = {}
        self.dic_dst2src = {}
        self.k_s2d = 0
        self.k_d2s = 0
        flow.udps.src_to_dst_second_bytes = 0
        flow.udps.dst_to_src_second_bytes = 0
        flow.udps.src_to_dst_avg_throughput = 0
        flow.udps.dst_to_src_avg_throughput = 0
        ###
        flow.udps.src_to_dst_second_bytes2 = 0
        flow.udps.dst_to_src_second_bytes2 = 0
        flow.udps.src_to_dst_avg_throughput2 = 0
        flow.udps.dst_to_src_avg_throughput2 = 0

        
        if packet.direction == 0:
            self.k_s2d = self.k_s2d + 1
            self.dic_src2dst[self.k_s2d] = {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}
        elif packet.direction == 1:
            self.k_d2s = self.k_d2s + 1
            self.dic_dst2src[self.k_d2s] = {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}
            
        
    def on_update(self, packet, flow):
        if packet.direction == 0:
            if self.k_s2d < 1:
                self.k_s2d = self.k_s2d + 1
                self.dic_src2dst[self.k_s2d] = {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}
            else:

                if self.dic_src2dst[self.k_s2d]['is_completed'] == True:
                    #print('completed s2d, key :', last_key)
                    self.k_s2d = self.k_s2d+ 1
                    #print('new key :', new_key)
                    self.dic_src2dst[self.k_s2d]= {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}
                else:
                    start = self.dic_src2dst[self.k_s2d]['start']
                    end = self.dic_src2dst[self.k_s2d]['end']
                    delta1 = (packet.time - start) / 1000
                    delta2 = (packet.time - end) / 1000
                    if delta1 <= 1:
                        self.dic_src2dst[self.k_s2d]['end']= packet.time
                        self.dic_src2dst[self.k_s2d]['size'] = self.dic_src2dst[self.k_s2d]['size'] + packet.ip_size
                        if delta1 == 1:
                            self.dic_src2dst[self.k_s2d]['is_completed'] = True
                    elif delta1 > 1:
                        self.dic_src2dst[self.k_s2d]['is_completed'] = True
                        if math.floor(delta2) >= 1:
                            for i in range(math.floor(delta2)):
                                self.k_s2d = self.k_s2d + i + 1
                                self.dic_src2dst[self.k_s2d]= {'is_completed':True, 'start': 0, 'end':0, 'size':0}
                            if delta2 % 1 != 0:
                                last_key = list(self.dic_src2dst.keys())[-1]
                                self.k_s2d = self.k_s2d + 1
                                self.dic_src2dst[self.k_s2d]= {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}             
                        else:
                            self.k_s2d = self.k_s2d + 1
                            self.dic_src2dst[self.k_s2d]= {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}
                        
        elif packet.direction == 1:
            if self.k_d2s < 1:
                self.k_d2s = self.k_d2s + 1
                self.dic_dst2src[self.k_d2s] = {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}
            else:
                if self.dic_dst2src[self.k_d2s]['is_completed']  == True:
                    #print('completed s2d, key :', last_key)
                    self.k_d2s = self.k_d2s+1
                    #print('new key :', new_key)
                    self.dic_dst2src[self.k_d2s]= {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}
                else:
                    start = self.dic_dst2src[self.k_d2s]['start']
                    end = self.dic_dst2src[self.k_d2s]['end']
                    delta1 = (packet.time - start) / 1000
                    delta2 = (packet.time - end) / 1000
                    if delta1 <= 1:
                        self.dic_dst2src[self.k_d2s]['end']= packet.time
                        self.dic_dst2src[self.k_d2s]['size'] = self.dic_dst2src[self.k_d2s]['size'] + packet.ip_size
                        if delta1 == 1:
                            self.dic_dst2src[self.k_d2s]['is_completed'] = True
                    elif delta1 > 1:
                        self.dic_dst2src[self.k_d2s]['is_completed'] = True
                        if math.floor(delta2) >= 1:
                            for i in range(math.floor(delta2)):
                                self.k_d2s = self.k_d2s + i + 1
                                self.dic_dst2src[self.k_d2s]= {'is_completed':True, 'start': 0, 'end':0, 'size':0}
                            if delta2 % 1 != 0:
                                self.k_d2s = self.k_d2s + 1
                                self.dic_dst2src[self.k_d2s]= {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}             
                        else:
                            self.k_d2s = self.k_d2s + 1
                            self.dic_dst2src[self.k_d2s]= {'is_completed':False, 'start': packet.time, 'end':packet.time, 'size':packet.ip_size}
        thpt_s2d = 0
        thpt_d2s = 0
        scb_s2d = 0
        scb_d2s = 0

        l_s2d = 0
        l_d2s = 0
        for k in list(self.dic_src2dst.keys()):
            size = self.dic_src2dst[k]['size']
            if size > 0:
                scb_s2d += size
                thpt_s2d += (8 * size)
                l_s2d += 1
        for k in list(self.dic_dst2src.keys()):
            size = self.dic_dst2src[k]['size']
            if size > 0:
                scb_d2s += size
                thpt_d2s += (8 * size)
                l_d2s += 1
        
        if l_s2d > 0:
            scb_s2d = scb_s2d / l_s2d
            thpt_s2d = thpt_s2d / l_s2d
        else:
            scb_s2d = flow.src2dst_bytes
            thpt_s2d = 8 * flow.src2dst_bytes
            
        if l_d2s > 0:
            scb_d2s = scb_d2s / l_d2s
            thpt_d2s = thpt_d2s / l_d2s
        else:
            scb_d2s = flow.dst2src_bytes
            thpt_d2s = 8 * flow.dst2src_bytes
       
        flow.udps.src_to_dst_second_bytes = scb_s2d 
        flow.udps.dst_to_src_second_bytes = scb_d2s 
        flow.udps.src_to_dst_avg_throughput = thpt_s2d
        flow.udps.dst_to_src_avg_throughput = thpt_d2s
        
        flow.udps.src_to_dst_second_bytes2 = flow.src2dst_bytes/(flow.src2dst_duration_ms/1000) if flow.src2dst_duration_ms > 0 else flow.src2dst_bytes
        flow.udps.dst_to_src_second_bytes2 = flow.dst2src_bytes/(flow.dst2src_duration_ms/1000) if flow.dst2src_duration_ms > 0 else flow.dst2src_bytes
        flow.udps.src_to_dst_avg_throughput2 = (8 * flow.src2dst_bytes/(flow.src2dst_duration_ms/1000)) if flow.src2dst_duration_ms > 0 else (8 * flow.src2dst_bytes)
        flow.udps.dst_to_src_avg_throughput2 = (8 * flow.dst2src_bytes/(flow.dst2src_duration_ms/1000)) if flow.dst2src_duration_ms > 0 else (8 * flow.dst2src_bytes)
    def on_expire(self, flow):
        thpt_s2d = 0
        thpt_d2s = 0
        scb_s2d = 0
        scb_d2s = 0
        l_s2d = 0
        l_d2s = 0
        for k in list(self.dic_src2dst.keys()):
            size = self.dic_src2dst[k]['size']
            if size > 0:
                scb_s2d += size
                thpt_s2d += (8 * size)
                l_s2d += 1
        for k in list(self.dic_dst2src.keys()):
            size = self.dic_dst2src[k]['size']
            if size > 0:
                scb_d2s += size
                thpt_d2s += (8 * size)
                l_d2s += 1
        
        if l_s2d > 0:
            scb_s2d = scb_s2d / l_s2d
            thpt_s2d = thpt_s2d / l_s2d
        else:
            scb_s2d = flow.src2dst_bytes
            thpt_s2d = 8 * flow.src2dst_bytes
            
        if l_d2s > 0:
            scb_d2s = scb_d2s / l_d2s
            thpt_d2s = thpt_d2s / l_d2s
        else:
            scb_d2s = flow.dst2src_bytes
            thpt_d2s = 8 * flow.dst2src_bytes
       
        flow.udps.src_to_dst_second_bytes = scb_s2d 
        flow.udps.dst_to_src_second_bytes = scb_d2s 
        flow.udps.src_to_dst_avg_throughput = thpt_s2d
        flow.udps.dst_to_src_avg_throughput = thpt_d2s
        
        flow.udps.src_to_dst_second_bytes2 = flow.src2dst_bytes/(flow.src2dst_duration_ms/1000) if flow.src2dst_duration_ms > 0 else flow.src2dst_bytes
        flow.udps.dst_to_src_second_bytes2 = flow.dst2src_bytes/(flow.dst2src_duration_ms/1000) if flow.dst2src_duration_ms > 0 else flow.dst2src_bytes
        flow.udps.src_to_dst_avg_throughput2 = (8 * flow.src2dst_bytes/(flow.src2dst_duration_ms/1000)) if flow.src2dst_duration_ms > 0 else (8 * flow.src2dst_bytes)
        flow.udps.dst_to_src_avg_throughput2 = (8 * flow.dst2src_bytes/(flow.dst2src_duration_ms/1000)) if flow.dst2src_duration_ms > 0 else (8 * flow.dst2src_bytes)
