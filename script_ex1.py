#!/usr/bin/python

'''
  SWI Labo 1 ex.1
  Author : Yann Lederrey & Joel Schär
'''

import sys
from scapy.all import *

devices = set()
# the script needs a mac adress to find
searchMac = sys.argv[1]
# multiple MAC adresses can be requested
numberMacToFind = len(sys.argv)-1

# If no mac address is given the scripts exit
if len(sys.argv)==1 : sys.exit("error, need Mac address as argument")

def PacketHandler(pkt) :
	if pkt.haslayer(Dot11) :
    # filter the packets to keep only probs
    if pkt.type == 0 and pkt.subtype == 4 :
		  dot11_layer = pkt.getlayer(Dot11)

      # Adding the equipement to the array if not already is in the list
      if dot11_layer.addr2 and ( dot11_layer.addr2 not in devices) :
	      devices.add(dot11_layer.addr2)

def stopfilter(x):
  ''' this function is supposed to stop in a certain case '''
	for x in xrange(1, numberMacToFind+1):
      # if the requested MAC addresse is found the infromation is printed
	    if (sys.argv[x] in devices):
        	if(sys.argv[x] != "ok"):
	            print ("found %s" %(sys.argv[x]))
	            sys.argv[x] = "ok"
		
# Starting the sniffing on the wlan0mon interface with a given function (PacketHandler)
# for each received packet. 
sniff(iface = "wlan0mon", prn = PacketHandler, stop_filter = stopfilter)

