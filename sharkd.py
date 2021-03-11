import pandas as pd
from pcapng_access import SharkdDataAccess


def get_json_bytes(json_string):
    return bytes((json_string + '\n'), 'utf-8')

def safe_float(string_in):
    try:
        out = float(string_in)
    except:
        out = None
    return out


class SharkdSession:
    json_trace = False
    s = ""
    is_connected = False
    rpcid = 0
    data_access = SharkdDataAccess()

    def __init__(self, ip_address, port):
        self.data_access.start_session(ip_address, port)
        self.is_connected = True

    def sharkd_load(self, filespec):
        params = f'"file":"{filespec}"'
        return self.data_access.rpc_send_recv('load', params )

    def sharkd_analyse(self):
        return self.data_access.rpc_send_recv('analyse', None)

    def sharkd_get_status(self):
        return self.data_access.rpc_send_recv('status', None)

    def set_config(self, params):
        data_out = self.data_access.rpc_send_recv('setconf', params)
        return

    def get_conversations_ip(self):
        params = '"tap0":"conv:IP"'
        data_out = self.data_access.rpc_send_recv('tap', params)[0]['result']['taps'][0]['convs']
        df = pd.DataFrame(data=data_out)
        df['proto'] = 'IP'
        return df

    def get_conversations_tcp(self):
        params = '"tap0":"conv:TCP"'
        data_out = self.data_access.rpc_send_recv('tap', params)[0]['result']['taps'][0]['convs']
        df = pd.DataFrame(data=data_out)
        df['proto'] = 'TCP'
        return df

    def get_conversations_udp(self):
        params = '"tap0":"conv:UDP"'
        data_out = self.data_access.rpc_send_recv('tap', params)[0]['result']['taps'][0]['convs']
        df = pd.DataFrame(data=data_out)
        df['proto'] = 'UDP'
        return df

    def get_conversations_sctp(self):
        params = '"tap0":"conv:SCTP"'
        data_out = self.data_access.rpc_send_recv('tap', params)[0]['result']['taps'][0]['convs']
        df = pd.DataFrame(data=data_out)
        df['proto'] = 'SCTP'
        return df

    def get_frame(self, framenum):
        params = f'"frame":{framenum}, "proto":true'
        return self.data_access.rpc_send_recv('frame', params)

    def get_frames(self, filter_expression, ws_fields):
        self.rpcid += 1
        index = 0
        pkt_list_cols = ''

        # make sure the data_access object knows the data type
        # for each field
        self.data_access.init_schema(ws_fields)

        for ws_field in ws_fields:
            pkt_list_cols += f'"column{index}":"{ws_field}:1"'
            index += 1

        if filter_expression == None:
            params = pkt_list_cols
        else:
            params = f'"filter":"{filter_expression}", {pkt_list_cols}'

        response, rsp_code, msg = self.data_access.rpc_send_recv('frames', params)
        pkts = response['result']

        data_out = []
        for pkt in pkts:
            new_row = []
            for j in range(len(ws_fields)):
                ######## MODIFy this to translate the value type
                new_row.append(self.data_access.switch_ftype(pkt['c'][j], j))
            data_out.append(new_row)

        df = pd.DataFrame(data=data_out)
        if df.size > 0:
            df.columns = ws_fields

        return df

    def get_dns(self, filter_expression) -> object:
        cols = [
            "frame.number",
            "ip.src",
            "ip.dst",
            "dns.flags.response",
            "dns.id",
            "dns.qry.name",
            "transum.art",
            "transum.status",
        ]
        if filter_expression:
            filter_exp = f'dns && ( {filter_expression} )'
        else:
            filter_exp = 'dns'

        return self.get_frames(filter_exp, cols)

    def get_rte(self, filter_exp) -> object:
        cols = [
            'frame.number',
            'ip.src',
            'tcp.srcport',
            'ip.dst',
            'tcp.dstport',
            'transum.art',
            'transum.st',
            'transum.reqspread',
            'transum.rspspread',
            'transum.status',
        ]

        return self.get_frames(filter_exp, cols)

    def get_ip_ttl(self) -> object:
        cols = [
            "frame.number",
            "ip.src",
            "ip.dst",
            "ip.ttl",
        ]
        filter_exp = 'ip'
        return self.get_frames(filter_exp, cols)

    def get_start_end(self) -> tuple[str, str]:
        status = self.sharkd_get_status()
        last_frame = int(status[0]['result']['frames'])
        cols = [
            "frame.number",
            "frame.time",
            "frame.time_epoch",
        ]
        first_frame_detail = self.get_frames('frame.number==1', cols)
        last_frame_detail  = self.get_frames(f'frame.number=={last_frame}', cols)
        return first_frame_detail['frame.time'][0], last_frame_detail['frame.time'][0]

    def get_expert(self):
        params = '"tap0":"expert"'
        expert_response = self.data_access.rpc_send_recv('tap', params)
        expert_pkts = expert_response[0]['result']['taps'][0]['details']
        return pd.DataFrame(data=expert_pkts)

    def get_tcp_seg_meta(self, data_only):
        cols = [
            'tcp.stream',
            'ip.src',
            'tcp.srcport',
            'ip.dst',
            'tcp.dstport',
            'frame.number',
            'frame.time_relative',
            'ip.id',
            'tcp.seq_raw',
            'tcp.ack_raw',
            'tcp.analysis.retransmission',
            'tcp.analysis.duplicate_ack_frame',
        ]
        if data_only:
            filter_exp = 'tcp.len>0'
        else:
            filter_exp = 'tcp'

        return self.get_frames(filter_exp, cols)

    def sharkd_close(self):
        self.data_access.close_session()
