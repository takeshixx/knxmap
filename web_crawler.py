import requests
import ipaddress
import multiprocessing
import time
import sys
import subprocess
import time
import datetime
import socket
import queue

def crawler(d,q,thread_number):
	st = '<title>'
	en = '</title>'
	while not q.empty():
		try:
			addr = q.get(timeout=1)	
			eibr = requests.get("http://"+str(addr)+"/bmxJava2/default.php",timeout=0.500)
			if (eibr.status_code) != 500 and (eibr.status_code) != 404 and (eibr.status_code) != 401 and (eibr.status_code) != 403 and (eibr.status_code) != 501:
				eibtitle = eibr.text[eibr.text.find(st)+len(st):eibr.text.find(en)]
				if 'eibPort' in eibtitle or 'Berker' in eibtitle or 'IP-Control' in eibtitle:
					d[addr]="http://"+str(addr)+"/bmxJava2/default.php - "+str(eibr.status_code)+" "+eibtitle+"\n"
			loxoner = requests.get("http://"+str(addr)+"/Login.html", timeout=0.500)
			if (loxoner.status_code) != 500 and (loxoner.status_code) != 404 and (loxoner.status_code) != 401 and (loxoner.status_code) != 403 and (loxoner.status_code) != 501:
				loxone_serv = loxoner.headers.get('server')
				if 'Loxone' in loxone_serv:
					d[addr]="http://"+str(addr)+"/Login.html - "+str(loxoner.status_code)+"\n"		
		except requests.exceptions.Timeout:
			pass
		except requests.exceptions.ConnectionError:
			pass
		except socket.timeout:
			pass
		except socket.error:
			pass
		except queue.Empty:
			pass
	q.task_done()

if __name__ == "__main__":
	with open('results.txt', 'a') as out:
                out.write(datetime.datetime.fromtimestamp(time.time()).strftime('%d-%m-%Y %H:%M:%S')+"\n")	
	manager = multiprocessing.Manager()
	d = manager.dict()
	q = manager.Queue()
	print ("Generating IP's")
	for addr in ipaddress.ip_network('84.149.0.0/16'):
		q.put(str(addr))
	jobs = []
	for a in range(10):
		p = multiprocessing.Process(target=crawler, args=(d,q,a))
		jobs.append(p)
		p.start()
	print ("Threads created, starting scan...")
	for a in jobs:
		a.join()
	with open('results.txt', 'a') as out:	
		for k in d.keys():
			out.write(str(k)+":"+str(d[k])+"\n")
		out.write(datetime.datetime.fromtimestamp(time.time()).strftime('%d-%m-%Y %H:%M:%S')+"\n")
