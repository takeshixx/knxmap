#! /usr/bin/env python2
import multiprocessing
import time
import sys
import subprocess

import knxlib


def worker(d,l,thread_number):

    while not l.empty():
        try:
            host = l.get(timeout=2)

            process = subprocess.Popen(["progmodestatus", "ip:localhost",str(host)],stdout=subprocess.PIPE)
            stdout =  process.stdout.readline()
            if "programming mode" in stdout:
                d[host]="online"
            else:
                d[host]=stdout.replace("\n","")
            time.sleep(1)
        except:
            pass

    l.task_done()


def main():
    try:
        manager = multiprocessing.Manager()
        d = manager.dict()
        l = manager.Queue()

        for a in range (2,3):
            for b in range (10,12):
                for c in range (100):
                    l.put(str(a)+"."+str(b)+"."+str(c))
        jobs = []
        for a in range(40):
            p = multiprocessing.Process(target=worker, args=(d,l,a))
            jobs.append(p)
            p.start()

        for a in jobs:
            a.join()

        with open('hosts', 'w') as out:
            for k in d.keys():
                out.write(str(k)+":"+str(d[k])+"\n")
    except:
        return 1


if __name__ == "__main__":
    sys.exit(main())