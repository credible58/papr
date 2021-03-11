############################################################################
# CONFIGURATION AREA
############################################################################

sharkd_server_ip = '127.0.0.1'
sharkd_server_port = 4446  # The port used by sharkd

# pcap_file = 'c:/traces/sharkd_data/one_hundred_packets.pcapng'
# pcap_file = 'c:/traces/Contoso_01/web01/web01_00001_20161012151754.pcapng'
# pcap_file = 'c:/traces/sharkd_data/skinny_and_ica.pcapng'
pcap_file = 'c:/traces/sharkd_data/skinny_and_ica_slice_100k.pcapng'
# pcap_file = 'c:/traces/sharkd_data/skinny_and_ica_slice_10k.pcapng'
#pcap_file = 'c:/traces/sharkd_data/dups_and_missing_segment.pcapng'

dup_pkts_threshold = 1000  # change this as needed
tcp_retrans_threshold = 0.01 # this is a percentage
tcp_retrans_consecutive = 0

############################################################################
# END OF CONFIGURATION AREA
############################################################################

import pandas as pd
import numpy as np
from sharkd import SharkdSession

def min_ms(x):
    return round(x.min() * 1000, 1)

def max_ms(x):
    return round(x.max() * 1000, 1)

def mean_ms(x):
    return round(x.mean() * 1000, 1)

def p95_ms(x):
    return round(x.quantile(0.95) * 1000, 1)

print('')
print('PACKET ANALYSIS PREPARATION REPORT')
print('')

sharkd_session = SharkdSession(sharkd_server_ip, sharkd_server_port)
if not sharkd_session.is_connected:
    print("Connection to the sharkd server has failed")
    exit(-1)

response, rc, error_msg = sharkd_session.sharkd_load(pcap_file)
if rc != 0:
    print(error_msg, end='')
    print(': ' + pcap_file)
    exit(-1)

response, rc, error_msg = sharkd_session.sharkd_get_status()

frame_count = response['result']['frames']

# produce the Summary information
start_time, end_time = sharkd_session.get_start_end()

print('Summary')
print('-------')
print('')
print(f'Filename:     {response["result"]["filename"]}')
print(f'No of frames: {frame_count}')
print(f'Start time:   {start_time}')
print(f'End time:     {end_time}')
print(f'Duration:     {response["result"]["duration"]} s')
print('')

# produce the Capture Quality information
print('Capture Quality')
print('---------------')
print('')

expert_df = sharkd_session.get_expert()
pkts_missed = 0

filt = (expert_df['s'] == 'Warning') \
       & (expert_df['g'] == 'Sequence') \
       & (expert_df['m'].str.startswith('Previous segment(s) not captured'))

pkts_missed = expert_df[filt]['f'].count()
del expert_df

print(f'Packets missed:       {pkts_missed}')


df = sharkd_session.get_tcp_seg_meta(False)
df.sort_values(by=['tcp.stream','ip.src','tcp.srcport'])

dup_pkts = 0
dup_pkts_max_delta = 0.0

for index, row in df.iterrows():
    if index > 0:
        if row['tcp.stream'] == previous_row['tcp.stream'] \
            and row['ip.src'] == previous_row['ip.src'] \
            and row['tcp.srcport'] == previous_row['tcp.srcport'] \
            and row['tcp.seq_raw'] == previous_row['tcp.seq_raw'] \
            and row['ip.id'] == previous_row['ip.id'] \
                :
            dup_pkts += 1
            if row['frame.time_relative'] - previous_row['frame.time_relative'] > dup_pkts_max_delta:
                dup_pkts_max_delta = row['frame.time_relative'] - previous_row['frame.time_relative']
    previous_row = row

del df

print(f'Duplicate packets:    {dup_pkts}')
print(f'Duplicates max delta: {dup_pkts_max_delta}')
print('')
print('Duplicate packet counts are based on TCP only, and so the actual')
print('number of duplicate packets may be higher than shown here.')
print('')

print('Service Endpoints')
print('-----------------')
print('')
print('| Proto    | IP Addr            | Port     |')
print('+----------+--------------------+----------+')

convs_detected = False

tcp_convs = sharkd_session.get_conversations_tcp()
if tcp_convs.size > 0:
    seps = tcp_convs.groupby(['proto', 'daddr', 'dport']).groups
    for key, values in seps.items():
        proto = "{:<8}".format(key[0])
        ip    = "{:<18}".format(key[1])
        port  = "{:<8}".format(key[2])
        print(f'| {proto} | {ip} | {port} |')

udp_convs = sharkd_session.get_conversations_udp()
if udp_convs.size > 0:
    seps = udp_convs.groupby(['proto', 'daddr', 'dport']).groups
    for key, values in seps.items():
        proto = "{:<8}".format(key[0])
        ip    = "{:<18}".format(key[1])
        port  = "{:<8}".format(key[2])
        print(f'| {proto} | {ip} | {port} |')

sctp_convs = sharkd_session.get_conversations_sctp()
if sctp_convs.size > 0:
    seps = sctp_convs.groupby(['proto', 'daddr', 'dport']).groups
    for key, values in seps.items():
        proto = "{:<8}".format(key[0])
        ip    = "{:<18}".format(key[1])
        port  = "{:<8}".format(key[2])
        print(f'| {proto} | {ip} | {port} |')

if convs_detected == False:
    print('* No service endpoints identified')

print('')
print('Route Stability')
print('---------------')
print('')
print('This table shows the level of variation in TTL value along a route.')
print('A value of zero means no change was detected.  The higher the std')
print('value, the greater the level of variance.')
print('')

df = sharkd_session.get_ip_ttl()
# use the following to create some variation during testing
# df.loc[2, 'ip.ttl'] = 127
# df.loc[100, 'ip.ttl'] = 126
# df.loc[1500, 'ip.ttl'] = 65
ttl_grp = df.groupby(['ip.src', 'ip.dst'])

ip_ttls = ttl_grp['ip.ttl'].agg(['min', 'max', 'std'])
filt = (ip_ttls['std'] > 0)
rv = ip_ttls[filt]
if rv.size > 0:
    print(rv)
else:
    print('* No route variance detected')

print('')
print('NB: The Route Stability assessment is only valid for the portion of the')
print('route from the source IP to the point where the packets were captured.')
print('')

print('')
print('Packet Loss')
print('-----------')
# print('')
# print(f'Threshold percentage: {tcp_retrans_threshold}%')
# print(f'Threshold for consecutive loss: {tcp_retrans_consecutive}')

# now get retransmission information
print('')
print('Excessive TCP Retransmissions')
print('')
print('Typically, we are interested in TCP retransmissions and Dup ACKs for each')
print('TCP connection, but here we are using this information as an indication of')
print('packet loss.  For that reason, we aggregate these numbers for all TCP traffic')
print('between IP address pairs.')
print('')


data_pkts = sharkd_session.get_tcp_seg_meta(True)

df = pd.DataFrame(data=data_pkts)
df.sort_values(by=['tcp.stream','ip.src','tcp.srcport'])

df2 = pd.DataFrame(columns=['ip.src', 'tcp.srcport', 'ip.dst', 'tcp.dstport', 'count'])
j = 0

for index, row in df.iterrows():
    if index > 0:
        if row['tcp.stream'] == previous_row['tcp.stream'] \
            and row['ip.src'] == previous_row['ip.src'] \
            and row['tcp.srcport'] == previous_row['tcp.srcport'] \
            and row['tcp.seq_raw'] == previous_row['tcp.seq_raw'] \
            and row['ip.id'] != previous_row['ip.id']:
            df2.loc[j] = [row['ip.src'], row['tcp.srcport'], row['ip.dst'], row['tcp.dstport'], 1]
            j += 1
    previous_row = row

retrans = df2.groupby(['ip.src', 'ip.dst'], as_index=False)['count'].count()

if retrans.shape[0] > 0:
    retrans.rename(columns={'count': '# of Retrans'}, inplace=True)
    pd.set_option('display.max_rows', 100)
    print(retrans)
else:
    print('* No TCP retransmissions seen')

# now get DUP ACK information
print('')
print('Excessive DUP ACKs')

df = sharkd_session.get_tcp_seg_meta(False)

filt = (df['tcp.analysis.duplicate_ack_frame'] != None)
df2 = df[filt]

dupack = df2.groupby(['ip.src', 'ip.dst'], as_index=False)['tcp.srcport'].count()

if dupack.shape[0] > 0:
    dupack.rename(columns={'tcp.srcport': '# of Dup ACKs'}, inplace=True)
    pd.set_option('display.max_rows', 100)
    print(dupack)
else:
    print('* No TCP Dup ACKs seen')
print('')

# produce DNS information
print('')
print('DNS')
print('---')
print('')

df = sharkd_session.get_dns(None)

print('DNS Servers Seen')
print('')

if df.size > 0:
    filt = (df['transum.status'] == 'OK')
    dns_stats = df.loc[filt].groupby(['ip.dst'], as_index=False)['transum.art'].count()
    if dns_stats.shape[0] > 0:
        dns_stats.rename(columns={'ip.dst': 'IP Addr', 'transum.art': '# of Requests'}, inplace=True)
        pd.set_option('display.max_rows', 100)
        print(dns_stats)
else:
    print('* No DNS servers seen')

print('')
print('DNS Servers Not Responding')
print('')

if df.size > 0:
    filt = (df['transum.status'] == 'Response missing')
    dns_stats = df.loc[filt].groupby(['ip.dst'], as_index=False)['transum.art'].count()
    if dns_stats.shape[0] > 0:
        dns_stats.rename(columns={'ip.dst': 'IP Addr', 'count': '# of Missing Responses'}, inplace=True)
        pd.set_option('display.max_rows', 100)
        print(dns_stats)
    else:
        print('* No DNS requests with missing responses seen')

print('')
print('DNS Service Errors')
print('')
print('* To be completed')
print('')

print('')
print('DNS Request Latency')
print('')

if df.size > 0:
    filt = (df['transum.status'] == 'OK')
    dns_stats = df.loc[filt].groupby(['ip.dst'], as_index=False)['transum.art'].agg([min_ms, max_ms, mean_ms, p95_ms])
    if dns_stats.shape[0] > 0:
        dns_stats.rename(columns={'ip.dst': 'IP Addr'}, inplace=True)
        pd.set_option('display.max_rows', 100)
        print(dns_stats)
else:
    print('* No DNS servers seen')

print('')
print('Service Performance')
print('-------------------')
print('')

transum_ports = ''
tcp_convs = sharkd_session.get_conversations_tcp()
sep_ports = tcp_convs.groupby(['dport']).groups
i = 0
for key, values in sep_ports.items():
    if i > 0:
        transum_ports += ','
    transum_ports += key
    i += 1

params = f'"name":"transum.tcp_port_ranges","value":"{transum_ports}"'
sharkd_session.set_config(params)
df = sharkd_session.get_rte('tcp && transum')
filt = (df['transum.status'] == 'OK')
transum_stats = df.loc[filt].groupby(['ip.dst', 'tcp.dstport'], as_index=False)['transum.art'].agg([min_ms, max_ms, mean_ms, p95_ms])
if transum_stats.shape[0] > 0:
    pd.set_option('display.max_rows', 100)
    print(transum_stats.sort_values(by=['tcp.dstport', 'ip.dst']))
else:
    print('* No Request-Response sessions seen')

print('')
print('Use the following details to set the TRANSUM dissector preferences in Wireshark.')
print('')
print(f'TCP service ports: {transum_ports}')
print('')

sharkd_session.sharkd_close()

exit(0)
