from glob import glob
import json
import os
from time import sleep, time
import uuid

from core.logger import Logger
from .plugins.FTP import AuxFTPFeatures
from .plugins.ICMP import AuxICMPFeatures
from .plugins.IP_layer import AuxPktMinMaxSizeFeatures, AuxRawIPPkt
from .plugins.TCP_layer import AuxPktRetransmissionFeatures, AuxTCPFlagsFeatures, AuxTCPWindowMinMAx
from .plugins.statistics import AuxPktSizeFeatures, AuxSecBytesFeatures
from util.nfstream_util import run_nfstream_async
from .util.functions import flow_to_dict
from model.configuration.extension import FeatureConfig
from core.database import __db__
from nfstream import NFStreamer
from nfstream.flow import NFlow

from .plugins.DNS import AuxDNSFeatures

from util.functions import loadConfig, relative

try:
    # load and parse configuration
    config = loadConfig(FeatureConfig, relative(__file__, './config.yaml'))

    # Get logger
    logger = Logger(config.log, __name__.split('.')[-1])
    i = 0
    t = time()

    def worker(inpt, source):
        global i, t
        
        pile = glob(os.path.expanduser(inpt)) if source == 'file' else inpt
        for src in pile:
            logger.debug('Using', source, src)

            # Start feature extraction using NFstream
            flow: NFlow
            for flow in run_nfstream_async(source=relative(__file__, src),
                                           snapshot_length=128,
                                           idle_timeout=600,
                                           active_timeout=3600 if source == 'file' else 60,
                                           accounting_mode=1,
                                           n_dissections=20,
                                           statistical_analysis=True,
                                           splt_analysis=0,
                                           udps=[
                                               AuxPktSizeFeatures(),
                                               AuxPktMinMaxSizeFeatures(),
                                               AuxTCPFlagsFeatures(),
                                               AuxTCPWindowMinMAx(),
                                               AuxICMPFeatures(),
                                               AuxDNSFeatures(),
                                               AuxFTPFeatures(),
                                               AuxPktRetransmissionFeatures(),
                                               AuxSecBytesFeatures(),
                                            #    AuxRawIPPkt()
                                           ],
                                           n_meters=0,
                                           performance_report=0):
                # print(flow.values()[:10])

                # Asasign flow id
                flow_id = uuid.uuid4().hex

                # Log feature extraction
                # logger.debug('Extracted & storing flow', flow_id)

                i += 1

                if time() - t > 3:
                    logger.debug(f'{i} items processed')
                    t = time()

                # Store flow in the database
                __db__.store('flow', flow_id, flow_to_dict(flow))

                # Publish the id of the flow extracted to the configured channels
                for ch in config.channels.publish:
                    __db__.publish(ch, flow_id)


    for inpt in config.channels.input.files or []: worker(inpt, 'file')
    if config.channels.input.interfaces: worker(config.channels.input.interfaces, 'interface')

                # sleep(1)

except KeyboardInterrupt:
    print('aight see ya')