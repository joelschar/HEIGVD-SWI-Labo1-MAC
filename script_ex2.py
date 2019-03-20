#!/usr/bin/python

'''
  SWI Labo 1 ex.2
  Author : Yann Lederrey & Joel Schär
'''

from __future__ import print_function
import json
import requests
import os
import sys
import threading
from scapy.all import *
from copy import deepcopy

clear = lambda: os.system('clear')
devices = set()
Macs = {}
vendors = {}

def PacketHandler(pkt) :
	if pkt.haslayer(Dot11) :
		dot11_layer = pkt.getlayer(Dot11)
		#filter the pakets to keep only probs
		if pkt.type == 0 and pkt.subtype== 4:
			#filter to avoid packets without SSID
			if dot11_layer.addr2 and dot11_layer.info:
				# if this Macs dictionnary  not already contain this MAC
				if Macs.get(dot11_layer.addr2,None) == None:
					Macs[dot11_layer.addr2] = []
					# add the dictionnary entry with MAC as key and SSID as value 
					Macs[dot11_layer.addr2].append(pkt.info)
				else :
					# check if  SSID not already in list for this MAC
					list = Macs.get(dot11_layer.addr2)
					if(pkt.info not in list) :
						# Append this new SSID
						Macs[dot11_layer.addr2].append(pkt.info)

# print Mac address with vendors every 2 seconds 
def showMac():

	#Make a deepcopy of Macs dictionnary to not interfer with PacketHandler function
	tempMacs = deepcopy(Macs)
	clear()

	#parse every found Mac
	for x in tempMacs:
		vendor = ''
		# check if the vendors of this Mac is already find
		if(vendors.get(x,None) == None):

			# Reverse MAC to get vendors
			data = json.loads(requests.get('https://macvendors.co/api/' + x + '/json').text)
			try :
				vendor = data['result']['company']
			except : 
				vendor = "not found"
		else:
			vendor = vendors.get(x)

		print(x + " (" + vendor + ")", end='')

		#parse every SSID for this MAC and print it correctly
		i = 0
		for y in tempMacs[x]:
			if(i == 0):
				if(i == len(tempMacs[x])-1):
					print(" - " + y, end='')
				else :
					print(" - " + y + " , ", end='')
                        elif(i == len(tempMacs[x])-1):
                                print(y, end='')
			else :
				print(y + " , ",end='')
			i+=1

		print(".")

	# restart function showMac every 2 seconds
	t=threading.Timer(2,showMac)
	t.start()


					
showMac()
sniff(iface = "mon0", prn = PacketHandler)
