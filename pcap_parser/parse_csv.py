import os
import re
import sys
import string
import gc
import datetime
import time
import pandas as pd
import numpy as np


# port
DNS = 53
NTP = 123
SSDP = 1900
# protocols
TCP = 6
UDP = 17
# random seed
SEED = 7
# non-IoT devices
NON_IOT = ['laptop', 'androidphone', 'macbook', 'iphone', 'macbookiphone', 'samsunggalaxytab', '']

# location that outputs will be saved in
data_path = 'data/'
dest_path = data_path + 'parsed_datasets/'
src_path = data_path + 'data_csv/'

# return dict of devices and their MAC address
def read_device_list(file_name='List_Of_Devices.txt'):
    df = pd.read_table(file_name, index_col='List of Devices',delimiter='\t+', engine='python')
    df['MAC ADDRESS'] = df['MAC ADDRESS'].str.replace(r' ', '')
    df.index = df.index.str.replace(r' ', '').str.lower()
    return df.to_dict()['MAC ADDRESS']

# converts list of device to pandas dataframe
def device_list_to_csv(output_file='DeviceList.csv'):
    devices = read_device_list()
    df = pd.DataFrame(devices.items(), columns=['Device', 'MAC'])
    df['isIoT'] = df['Device'].apply(lambda x: 0 if x in NON_IOT else 1)
    df.to_csv(output_file)
    return df

# get index from 'col' that contain 'find_str'
# def find_string(df, col, find_str):
#     indx = df[col].apply(lambda x: True if find_str in x else False)
#     return list(df[indx].index)

# get index from columns in dataframe that contain 'find_str'
def find_match(df, src_col, dst_col, find_str):
    indx_1 = df[src_col].apply(lambda x: True if find_str in x else False)
    indx_2 = df[dst_col].apply(lambda x: True if find_str in x else False)
    l1 = list(df[indx_1].index)
    l2 = list(df[indx_2].index)
    return list(set(l1).intersection(l2))

def count_packets(db, byte_col, pkt_col):
    out_db = db.copy()
    out_db[pkt_col] = 0
    out_db.loc[out_db[byte_col] != 0, pkt_col] = 1
    out_db.loc[out_db[byte_col] == 0, pkt_col] = 0
    # return out_db
    return out_db.groupby(['MAC_addr', 'TIME']).agg(np.sum).reset_index()


def parse_data(start_time=0, end_time=86400):
    start_time = time.time()
    device_count = 0
    device_list = device_list_to_csv()

    if not os.path.exists(dest_path):
        os.makedirs(dest_path)

    # for _, row in device_list.iterrows():
    #     target_MAC = row['MAC']
    #     target_device = row['Device']
    #     device_count += 1

    for day in os.listdir(src_path):
        if '.csv' not in day: continue
        try:
            IoT_df = pd.read_csv(src_path + day)
            # reduce file-size
            IoT_df = IoT_df.astype({
                'TIME': 'int32', 'Size': 'uint16', 
                'IP.proto': 'uint16', 'port.src': 'uint16',
                'port.dst': 'uint16'
            })
        except:
            print('Cannot read {}'.format(day))
    
        # start time at midnihgt, time = 0
        IoT_df['TIME'] = IoT_df['TIME'] - IoT_df['TIME'][0]
        # restrict dataframe time (start_time tp end_time)
        if end_time == -1:
            IoT_df = IoT_df.loc[IoT_df['TIME'] >= start_time]
        else:
            IoT_df = IoT_df.loc[IoT_df['TIME'] < end_time]

        # get indices of local packets
        local_indx = find_match(IoT_df, 'IP.dst', 'IP.src', '192.168.1.')
        # get local packets
        local = IoT_df.iloc[local_indx]
        # get external packets
        external = IoT_df.drop(IoT_df.index[local_indx], axis=0)

        ############### Local Parsing ###############
        # outgoind SSDP - protocol: 17, port: 1900
        ssdp_out = pd.DataFrame()
        ssdp_out = local[local['port.src'] == SSDP].loc[:, ['eth.src', 'TIME', 'Size']]
        ssdp_out.rename(columns={'eth.src': 'MAC_addr', 'Size': 'SSDP.Out'}, inplace=True)
        ssdp_out = count_packets(ssdp_out, 'SSDP.Out', 'SSDP.Packet.Out')

        # local incoming packets
        local_in = pd.DataFrame()
        local_in = local.loc[:, ['eth.dst', 'TIME', 'Size']]
        local_in.rename(columns={'eth.dst': 'MAC_addr', 'Size': 'Local.In'}, inplace=True)
        local_in = count_packets(local_in, 'Local.In', 'Local.Packet.In')

        # local outgoing packets
        local_out = pd.DataFrame()
        local_out = local.loc[:, ['eth.src', 'TIME', 'Size']]
        local_out.rename(columns={'eth.src': 'MAC_addr', 'Size': 'Local.Out'}, inplace=True)
        local_out = count_packets(local_out, 'Local.Out', 'Local.Packet.Out')

        ############### External Parsing ###############
        # incoming DNS - port.src = 53
        dns_in = pd.DataFrame()
        dns_in = external[external['port.src'] == DNS].loc[:, ['eth.dst', 'TIME', 'Size', ]]
        dns_in.rename(columns={'eth.dst': 'MAC_addr', 'Size': 'DNS.In'}, inplace=True)
        dns_in = count_packets(dns_in, 'DNS.In', 'DNS.Packet.In')

        # outgoing DNS - port.dst = 53
        dns_out = pd.DataFrame()
        dns_out = external[external['port.dst'] == DNS].loc[:, ['eth.src', 'TIME', 'Size']]
        dns_out.rename(columns={'eth.src': 'MAC_addr', 'Size': 'DNS.Out'}, inplace=True)
        dns_out = count_packets(dns_out, 'DNS.Out', 'DNS.Packet.Out')

        # incoming NTP - port.src = 123
        ntp_in = pd.DataFrame()
        ntp_in = external[external['port.src'] == NTP].loc[:, ['eth.dst', 'TIME', 'Size']]
        ntp_in.rename(columns={'eth.dst': 'MAC_addr', 'Size': 'NTP.In'}, inplace=True)
        ntp_in = count_packets(ntp_in, 'NTP.In', 'NTP.Packet.In')

        # outgoing NTP - port.dst = 123
        ntp_out = pd.DataFrame()
        ntp_out = external[external['port.dst'] == NTP].loc[:, ['eth.src', 'TIME', 'Size']]
        ntp_out.rename(columns={'eth.src': 'MAC_addr', 'Size': 'NTP.Out'}, inplace=True)
        ntp_out = count_packets(ntp_out, 'NTP.Out', 'NTP.Packet.Out')

        # incoming TCP - IP.proto = 6, exclude NTP and DNS requests/responses
        tcp_in = pd.DataFrame()
        tcp_in = external[external['IP.proto'] == TCP]
        tcp_in = tcp_in.loc[(tcp_in['port.src'] != NTP) & (tcp_in['port.dst'] != NTP)]
        tcp_in = tcp_in.loc[(tcp_in['port.src'] != DNS) & (tcp_in['port.dst'] != DNS)]
        tcp_in = tcp_in.loc[:, ['eth.dst', 'TIME', 'Size']]
        tcp_in.rename(columns={'eth.dst': 'MAC_addr', 'Size': 'TCP.In'}, inplace=True)
        tcp_in = count_packets(tcp_in, 'TCP.In', 'TCP.Packet.In')

        # outgoing TCP - IP.proto = 6, exclude NTP and DNS requests/responses
        tcp_out = pd.DataFrame()
        tcp_out = external[external['IP.proto'] == TCP]
        tcp_out = tcp_out.loc[(tcp_out['port.src'] != NTP) & (tcp_out['port.dst'] != NTP)]
        tcp_out = tcp_out.loc[(tcp_out['port.src'] != DNS) & (tcp_out['port.dst'] != DNS)]
        tcp_out = tcp_out.loc[:, ['eth.src', 'TIME', 'Size']]
        tcp_out.rename(columns={'eth.src': 'MAC_addr', 'Size': 'TCP.Out'}, inplace=True)
        tcp_out = count_packets(tcp_out, 'TCP.Out', 'TCP.Packet.Out')

        # incoming UDP - IP.proto = 17, exclude NTP and DNS requests/responses
        udp_in = pd.DataFrame()
        udp_in = external[external['IP.proto'] == UDP]
        udp_in = udp_in.loc[(udp_in['port.src'] != NTP) & (udp_in['port.dst'] != NTP)]
        udp_in = udp_in.loc[(udp_in['port.src'] != DNS) & (udp_in['port.dst'] != DNS)]
        udp_in = udp_in.loc[:, ['eth.dst', 'TIME', 'Size']]
        udp_in.rename(columns={'eth.dst': 'MAC_addr', 'Size': 'UDP.In'}, inplace=True)
        udp_in = count_packets(udp_in, 'UDP.In', 'UDP.Packet.In')

        # outgoing UDP - IP.proto = 17, exclude NTP and DNS requests/responses
        udp_out = pd.DataFrame()
        udp_out = external[external['IP.proto'] == UDP]
        udp_out = udp_out.loc[(udp_out['port.src'] != NTP) & (udp_out['port.dst'] != NTP)]
        udp_out = udp_out.loc[(udp_out['port.src'] != DNS) & (udp_out['port.dst'] != DNS)]
        udp_out = udp_out.loc[:, ['eth.src', 'TIME', 'Size']]
        udp_out.rename(columns={'eth.src': 'MAC_addr', 'Size': 'UDP.Out'}, inplace=True)
        udp_out = count_packets(udp_out, 'UDP.Out', 'UDP.Packet.Out')

        # combine all dataframes
        final_df = pd.DataFrame()
        final_df = final_df.append(ssdp_out, sort=False)
        final_df = final_df.append(local_in, sort=False)
        final_df = final_df.append(local_out, sort=False)
        final_df = final_df.append(dns_in, sort=False)
        final_df = final_df.append(dns_out, sort=False)
        final_df = final_df.append(ntp_in, sort=False)
        final_df = final_df.append(ntp_out, sort=False)
        final_df = final_df.append(tcp_in, sort=False)
        final_df = final_df.append(tcp_out, sort=False)
        final_df = final_df.append(udp_in, sort=False)
        final_df = final_df.append(udp_out, sort=False)

        final_df = final_df.groupby(['TIME', 'MAC_addr'], sort=True).agg(np.sum).reset_index()

        # drop rows with MAC_addr not in device list
        devices = read_device_list().values()
        ind = list(final_df['MAC_addr'].apply(lambda x: 1 if x in devices else np.nan).dropna().index)
        final_df = final_df.iloc[ind].reset_index().drop(columns='index')
        
        final_df.to_csv(dest_path + 'parsed_' + day, index=True)
        print('parsed {}'.format(day))

def fill_missing(separate_device=False):

    path = data_path + 'filled_datasets/'
    if not os.path.exists(path):
        os.makedirs(path)

    devices = read_device_list()

    for f in os.listdir(dest_path):

        if '.csv' not in f: continue
        df = pd.read_csv(dest_path + f)
        df.drop(columns='Unnamed: 0', inplace=True)
        filled_df = pd.DataFrame()
        
        for mac in df['MAC_addr'].unique():
            tmp = df[df['MAC_addr'] == mac].set_index('TIME').reindex(range(0, 86400), fill_value=0)
            tmp['MAC_addr'] = mac
            filled_df = filled_df.append(tmp.reset_index(), sort=False)
        filled_df = filled_df.reset_index().drop(columns='index')
        
        if separate_device:
            for mac in filled_df['MAC_addr'].unique():
                tmp = filled_df[filled_df['MAC_addr'] == mac].copy()
                tmp.drop(columns='MAC_addr', inplace=True)
                tmp = tmp.reset_index().drop(columns='index')
                dev = list(devices.keys())[list(devices.values()).index(mac)]
                tmp.set_index('TIME')
                tmp.to_csv(path + dev + '_' + f.replace('parsed_', ''), index=False)
                print('filled missing rows, {}'.format(dev + '_' + f.replace('parsed_', '')))
        else:
            filled_df.set_index('TIME')
            filled_df.to_csv(path + f, index=False)
            print('filled missing rows, {}'.format(path + f))


if __name__ == '__main__':

    print('parsing csv ...')
    parse_data()
    print('Completed\n\n')

    print('fill missing zero ...')
    # fill_missing(separate_device=False)
    fill_missing(separate_device=True)
    print('Completed\n')
