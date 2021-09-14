import csv
import dpkt
import os
import socket
import struct
import sys
import time

from constants import *


# taken from "https://dpkt.readthedocs.io/en/latest/_modules/examples/print_packets.html"
def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % dpkt.compat.compat_ord(b) for b in address)

# taken from "https://dpkt.readthedocs.io/en/latest/_modules/examples/print_packets.html"
def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def pcap_to_csv(pcap_file):

    header = [
        'Packet ID', 'TIME', 'Size', 
        'eth.src', 'eth.dst', 'IP.src', 'IP.dst',
        'IP.proto', 'port.src', 'port.dst'
    ]

    csv_file = pcap_file.replace('.pcap', '.csv').replace(DATA_PATH, RAW_CSV_PATH)

    with open(csv_file, 'w') as csv_f:

        temp_data = {
            'Packet ID': 0, 'TIME': 0, 'Size': 0, 
            'eth.src': '', 'eth.dst': '', 'IP.src': '', 'IP.dst': '', 
            'IP.proto': '', 'port.src': '', 'port.dst': ''
        }
        csv_writer = csv.DictWriter(csv_f, fieldnames=header)
        csv_writer.writeheader()

        with open(pcap_file, 'rb') as pcap_f:

            pcap = dpkt.pcap.Reader(pcap_f)
            packet_id = 0

            for ts, buf in pcap:

                # handling truncated packet
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError,Exception) as e:
                    print('\nError Parsing DNS, Might be a truncated packet...')
                    print('Exception: {!r}\n'.format(e))
                    continue

                ip = eth.data
                packet_id += 1

                # check if EtherType is 0x0800 (used by IPv4), or 2048 (in decimal)
                if (eth.type != dpkt.ethernet.ETH_TYPE_IP): continue
                # check if the Ethernet frame contains an IP packet
                if not isinstance(ip, dpkt.ip.IP): continue

                temp_data['Packet ID'] = packet_id
                temp_data['TIME'] = int(ts)
                temp_data['Size'] = len(buf)
                # temp_data['size'] = ip.len
                temp_data['eth.src'] = mac_addr(eth.src)
                temp_data['eth.dst'] = mac_addr(eth.dst)
                temp_data['IP.src'] = inet_to_str(ip.src)
                temp_data['IP.dst'] = inet_to_str(ip.dst)
                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    temp_data['IP.proto'] = TCP
                    if isinstance(ip.data, bytes):
                        # handle invalid header length
                        try:
                            temp_data['port.src'] = dpkt.tcp.TCP(ip.data).sport
                            temp_data['port.dst'] = dpkt.tcp.TCP(ip.data).dport
                        except:
                            print('invalid header length')
                            continue
                    else:
                        temp_data['port.src'] = ip.tcp.sport
                        temp_data['port.dst'] = ip.tcp.dport
                elif ip.p == dpkt.ip.IP_PROTO_UDP:
                    temp_data['IP.proto'] = UDP
                    if isinstance(ip.data, bytes):
                        temp_data['port.src'] = dpkt.udp.UDP(ip.data).sport
                        temp_data['port.dst'] = dpkt.udp.UDP(ip.data).dport
                    else:
                        temp_data['port.src'] = ip.udp.sport
                        temp_data['port.dst'] = ip.udp.dport
                else:
                    continue

                csv_writer.writerow(temp_data)

def convert_file():

    if not os.path.exists(RAW_CSV_PATH):
        os.makedirs(RAW_CSV_PATH)

    print('converting pcap to csv ...')
    for f in os.listdir(DATA_PATH):
        if '.pcap' not in f: continue
        pcap_to_csv('{}{}'.format(DATA_PATH, f))
        print('{} completed'.format(f))


if __name__ == '__main__':

    convert_file()
