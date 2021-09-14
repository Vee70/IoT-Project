DATA_PATH = 'data/'
# path to raw csv files converted from pcap files
RAW_CSV_PATH = DATA_PATH + 'raw_csv/'
# path to datasets that will be used in training
DATA_FINAL_PATH = DATA_PATH + 'final_datasets/'

# random seed
SEED = 7

# port
DNS = 53
NTP = 123
SSDP = 1900
# protocols
TCP = 6
UDP = 17

# non-IoT devices
NON_IOT = [
    'laptop', 'androidphone', 'macbook', 'iphone',
    'macbookiphone', 'samsunggalaxytab', ''
]