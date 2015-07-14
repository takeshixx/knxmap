#!/usr/bin/python
import sys
import pprint
from collections import defaultdict
import collections

pp = pprint.PrettyPrinter(depth=6)
f = open('all.txt', 'r')
hosts ={}
sender = []
receiver = []
for line in f:
	send = line.split()[2]
	if send not in sender:
		sender.append(send)
	recv = line.split()[4]
	recv = recv.rstrip(":")
	if recv not in receiver:
		receiver.append(recv)
	if send in hosts:
		hosts[send][recv] += 1        
	else:
		d={}
		d = defaultdict(lambda: 0, d)
		hosts[send] = d
		hosts[send][recv] += 1
f.close()
hosts2 = collections.OrderedDict(sorted(hosts.items()))
for key in hosts2:
	print (key)
	for key2 in hosts2[key]:
		print ("\t"+key2,hosts2[key][key2])
sender.sort()
receiver.sort()

