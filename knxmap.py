#! /usr/bin/env python2
import multiprocessing
import time
import sys
import subprocess
import socket

import libknx
import libknx.messages

import asyncio

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


class KnxDescription:

    def __init__(self, loop, port=55775):
        self.loop = loop
        self.transport = None


    def connection_made(self, transport):
        print("got connection")
        self.transport = transport
        packet = libknx.messages.KnxDescriptionRequest(port=port)
        packet.set_source_ip('192.168.178.19')
        packet.pack_knx_message()
        print(packet.get_message())
        self.transport.sendto(packet.get_message())

    def datagram_received(self, data, addr):
        print("received datagram")
        #message = data.decode()
        print(data)
        print(type(data))
        #print('Received %r from %s' % (message, addr))
        #print('Send %r to %s' % (message, addr))
        #self.transport.sendto(data, addr)

        response = libknx.messages.KnxDescriptionResponse(data)
        print(response.header)
        print(response.body)

        self.transport.close()


    def error_received(self, exc):
        print('Error received:', exc)

    def connection_lost(self, exc):
        print("Socket closed, stop the event loop")
        loop = asyncio.get_event_loop()
        loop.stop()



class KnxConnect:

    def __init__(self, loop, port=55775):
        self.loop = loop
        self.transport = None

    def connection_made(self, transport):
        print("got connection")
        self.transport = transport
        packet = libknx.messages.KnxConnectionRequest(port=port)
        packet.set_source_ip('192.168.178.19')
        packet.pack_knx_message()
        print(packet.get_message())
        self.transport.sendto(packet.get_message())

    def datagram_received(self, data, addr):
        print("received datagram")
        print(data)
        print(type(data))

        response = libknx.messages.KnxConnectionResponse(data)
        print(response.header)
        print(response.body)

        self.transport.close()

    def error_received(self, exc):
        print('Error received:', exc)

    def connection_lost(self, exc):
        print("Socket closed, stop the event loop")
        loop = asyncio.get_event_loop()
        loop.stop()


if __name__ == "__main__":
    port = 55779
    loop = asyncio.get_event_loop()
    print("Starting UDP server")
    # One protocol instance will be created to serve all client requests
    # connect = loop.create_datagram_endpoint(
    #     lambda: KnxDescription(loop, port),
    #     local_addr=('192.168.178.19', port),
    #     remote_addr=('192.168.178.11', 3671)
    # )

    connect = loop.create_datagram_endpoint(
        lambda: KnxConnect(loop, port),
        local_addr=('192.168.178.19', port),
        remote_addr=('192.168.178.20', 3671)
    )

    transport, protocol = loop.run_until_complete(connect)
    loop.run_forever()
    transport.close()
    loop.close()



# def main():
#     try:
#         manager = multiprocessing.Manager()
#         d = manager.dict()
#         l = manager.Queue()
#
#         for a in range (2,3):
#             for b in range (10,12):
#                 for c in range (100):
#                     l.put(str(a)+"."+str(b)+"."+str(c))
#
#         jobs = []
#         for a in range(40):
#             p = multiprocessing.Process(target=worker, args=(d,l,a))
#             jobs.append(p)
#             p.start
#
#         for a in jobs:
#             a.join()
#
#         with open('hosts', 'w') as out:
#             for k in d.keys():
#                 out.write(str(k)+":"+str(d[k])+"\n")
#     except:
#         return 1


# if __name__ == "__main__":
#     sys.exit(main())