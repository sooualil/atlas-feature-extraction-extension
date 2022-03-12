from nfstream.flow import NFlow

def flow_to_dict(flow: NFlow):
    return {key: getattr(flow.udps, key.split('.')[-1]) if 'udps.' in key else getattr(flow, key) for key in flow.keys()}

