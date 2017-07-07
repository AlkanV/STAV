#!/usr/bin/env python
import sys
from CFGClass import *

CONFIGDISPLAY = (
'Enabled'
'| Benchmark  '
'| Server List File '
'| Threads '
'| Target IP '
'| Output File '
'| Port '
'| Packet Count '
'| Packet Size'
'| Flooding'
'| Method '
'| Concurrent Socket '
'| Debug '
'\n{}').format('-'*75)

class ConfigFileHelper(object):
	def __init__(self,RawConfigParser,ConfigFilePath):
		configParser = RawConfigParser
		configFilePath = ConfigFilePath
		configParser.read(configFilePath)

		self.dnsAmp = DNSAmplificatonCFG(configParser,configFilePath)
		self.ntpAmp = NTPAmplificatonCFG(configParser,configFilePath)
		self.snmpAmp = SNMPAmplificatonCFG(configParser,configFilePath)
		self.ssdpAmp = SSDPAmplificatonCFG(configParser,configFilePath)
		self.synFlood = SYNFloodCFG(configParser,configFilePath)
		self.httpFlood = HTTPFloodCFG(configParser,configFilePath)
	def printCfgProperties(self):
		self.dnsAmp.printProperties()
		self.ntpAmp.printProperties()
		self.snmpAmp.printProperties()
		self.ssdpAmp.printProperties()
		self.synFlood.printProperties()
		self.httpFlood.printProperties()

	def writeChangesToConfigFile(self):
		print 'Config file updated succesfully.'
		self.printCfgProperties()

class DNSAmplificatonCFG(object):
	def __init__(self,RawConfigParser,ConfigFilePath):
		configParser = RawConfigParser
		configFilePath = ConfigFilePath
		configParser.read(configFilePath)
		self.className='DNSAmplificaton'
		self.enabled = configParser.get(self.className, 'enabled')
		self.benchmark = configParser.get(self.className, 'benchmark')
		self.dnsServerList =  configParser.get(self.className, 'dnsServerList')
		self.threads = int(configParser.get(self.className, 'threads'))
		self.targetIp = configParser.get(self.className, 'targetIp')
		self.outputFile = configParser.get(self.className, 'outputFile')
	def printProperties(self):
		print self.className
		print 'Enabled: ' + self.enabled
		print 'Benchmark: ' + self.benchmark
		print 'DNS Server List: ' + self.dnsServerList
		print 'Threads: ' + str(self.threads)
		print 'Target IP: ' + self.targetIp
		print 'Output File: ' + self.outputFile
		print

class NTPAmplificatonCFG(object):
	def __init__(self,RawConfigParser,ConfigFilePath):
		configParser = RawConfigParser
		configFilePath = ConfigFilePath
		configParser.read(configFilePath)
		self.className='NTPAmplificaton'
		self.enabled = configParser.get(self.className, 'enabled')
		self.benchmark = configParser.get(self.className, 'benchmark')
		self.ntpServerList =  configParser.get(self.className, 'ntpServerList')
		self.threads = int(configParser.get(self.className, 'threads'))
		self.targetIp = configParser.get(self.className, 'targetIp')
		self.outputFile = configParser.get(self.className, 'outputFile')
	def printProperties(self):
		print self.className
		print 'Enabled: ' + self.enabled
		print 'Benchmark: ' + self.benchmark
		print 'NTP Server List: ' + self.ntpServerList
		print 'Threads: ' + str(self.threads)
		print 'Target IP: ' + self.targetIp
		print 'Output File: ' + self.outputFile
		print

class SNMPAmplificatonCFG(object):
	def __init__(self,RawConfigParser,ConfigFilePath):
		configParser = RawConfigParser
		configFilePath = ConfigFilePath
		configParser.read(configFilePath)
		self.className='SNMPAmplificaton'
		self.enabled = configParser.get(self.className, 'enabled')
		self.benchmark = configParser.get(self.className, 'benchmark')
		self.snmpServerList =  configParser.get(self.className, 'snmpServerList')
		self.threads = int(configParser.get(self.className, 'threads'))
		self.targetIp = configParser.get(self.className, 'targetIp')
		self.outputFile = configParser.get(self.className, 'outputFile')

	def printProperties(self):
		print self.className
		print 'Enabled: ' + self.enabled
		print 'Benchmark: ' + self.benchmark
		print 'SNMP Server List: ' + self.snmpServerList
		print 'Threads: ' + str(self.threads)
		print 'Target IP: ' + self.targetIp
		print 'Output File: ' + self.outputFile
		print

class SSDPAmplificatonCFG(object):
	def __init__(self,RawConfigParser,ConfigFilePath):
		configParser = RawConfigParser
		configFilePath = ConfigFilePath
		configParser.read(configFilePath)
		self.className='SSDPAmplificaton'
		self.enabled = configParser.get(self.className, 'enabled')
		self.benchmark = configParser.get(self.className, 'benchmark')
		self.ssdpServerList =  configParser.get(self.className, 'ssdpServerList')
		self.threads = int(configParser.get(self.className, 'threads'))
		self.targetIp = configParser.get(self.className, 'targetIp')
		self.outputFile = configParser.get(self.className, 'outputFile')
	def printProperties(self):
		print self.className
		print 'Enabled: ' + self.enabled
		print 'Benchmark: ' + self.benchmark
		print 'SSDP Server List: ' + self.ssdpServerList
		print 'Threads: ' + str(self.threads)
		print 'Target IP: ' + self.targetIp
		print 'Output File: ' + self.outputFile
		print

class SYNFloodCFG(object):
	def __init__(self,RawConfigParser,ConfigFilePath):
		configParser = RawConfigParser
		configFilePath = ConfigFilePath
		configParser.read(configFilePath)
		self.className = 'SYNFlood'
		self.enabled = configParser.get(self.className, 'enabled')
		self.benchmark = configParser.get(self.className, 'benchmark')
		self.targetIp = configParser.get(self.className, 'targetIp')
		self.port = configParser.get(self.className, 'port')
		self.packetCount = int(configParser.get(self.className, 'packetCount'))
		self.packetSize = int(configParser.get(self.className, 'packetSize'))
		self.windowSize = int(configParser.get(self.className, 'windowSize'))
		self.flooding = configParser.get(self.className, 'flooding')
		self.outputFile = configParser.get(self.className, 'outputFile')

	def printProperties(self):
		print self.className
		print 'Enabled: ' + self.enabled
		print 'Benchmark: ' + self.benchmark
		print 'Target IP: ' + self.targetIp
		print 'Port: ' + self.port
		print 'Packet Count: ' + str(self.packetCount)
		print 'Packet Size: ' + str(self.packetSize)
		print 'Window Size: ' + str(self.windowSize)
		print 'Flooding: ' + self.flooding
		print 'Output File: ' + self.outputFile
		print


class HTTPFloodCFG(object):
	def __init__(self,RawConfigParser,ConfigFilePath):
		configParser = RawConfigParser
		configFilePath = ConfigFilePath
		configParser.read(configFilePath)
		self.className = 'HTTPFlood'
		self.enabled = configParser.get(self.className, 'enabled')
		self.benchmark = configParser.get(self.className, 'benchmark')
		self.targetURL = configParser.get(self.className, 'targetURL')
		self.threads = int(configParser.get(self.className, 'threads'))
		self.numberOfSocket = int(configParser.get(self.className, 'numberOfSocket'))
		self.method = configParser.get(self.className, 'method')
		self.debug = int(configParser.get(self.className, 'debug'))
		self.outputFile = configParser.get(self.className, 'outputFile')
	def printProperties(self):
		print self.className
		print 'Enabled: ' + self.enabled
		print 'Benchmark: ' + self.benchmark
		print 'Target URL: ' + self.targetURL
		print 'Threads: ' + str(self.threads)
		print 'Number of Socket: ' + str(self.numberOfSocket)
		print 'Method: ' + self.method
		print 'Debug: ' + str(self.debug)
		print 'Output File: ' + self.outputFile
		print


			# dnsAmp = DNSAmplificatonCFG(configParser,configFilePath)
			# dnsAmp.printProperties()
			# dnsAmp.threads = 20
			# dnsAmp.benchmark = 'yes'
			# dnsAmp.printProperties()
			#
			# ntpAmp = NTPAmplificatonCFG(configParser,configFilePath)
			# ntpAmp.printProperties()
			# ntpAmp.threads = 35
			# ntpAmp.enabled = 'yes'
			# ntpAmp.printProperties()
			#
			# snmpAmp = SNMPAmplificatonCFG(configParser,configFilePath)
			# snmpAmp.printProperties()
			# snmpAmp.threads = 100
			# snmpAmp.outputFile = 'New_Output_File'
			# snmpAmp.printProperties()
			#
			# ssdpAmp = SSDPAmplificatonCFG(configParser,configFilePath)
			# ssdpAmp.printProperties()
			# ssdpAmp.threads = 100
			# ssdpAmp.outputFile = 'New_Output_File'
			# ssdpAmp.printProperties()
			#
			# synFlood = SYNFloodCFG(configParser,configFilePath)
			# synFlood.printProperties()
			# synFlood.port = 5555
			# synFlood.printProperties()
			#
			# httpFlood = HTTPFloodCFG(configParser,configFilePath)
			# httpFlood.printProperties()
			# httpFlood.method = 'post'
			# httpFlood.numberOfSocket = 200
			# httpFlood.printProperties()'''
			# '''print configParser.get('DNSAmplificaton', 'benchmark')
			# print configParser.get('NTPAmplificaton', 'TargetIp')
			# print configParser.get('SNMPAmplificaton', 'threads')
			# print configParser.get('SSDPAmplificaton', 'outputFile')
			# print configParser.get('SYNFlood', 'port')
			# print configParser.get('HTTPFlood', 'method')
