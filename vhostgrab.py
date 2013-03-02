#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" vhostgrab.py

    vhostGrab is a virtual host enumeration script.

    This script was inspired by vhostchecker.pl
     (http://www.cyberis.co.uk/downloads/vhostchecker.pl).

    Author: marpie (marpie@a12d404.net)

    Last Update:  20130302
    Created:      20130302

"""
import socket
import ssl
import argparse
import os
import time
from threading import Thread
from Queue import Queue

# Version Information
__version__ = "0.0.1"
__program__ = "vhostgrab v" + __version__
__author__ = "marpie"
__email__ = "marpie+vhostgrab@a12d404.net"
__license__ = "BSD License"
__copyright__ = "Copyright 2013, a12d404.net"
__status__ = "Prototype"  # ("Prototype", "Development", "Testing", "Production")

SCRIPT_PATH = os.path.dirname( os.path.realpath( __file__ ) )


REQUEST = """GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64; rv:19.0) Gecko/20100101 Firefox/19.0\r\n\r\n"""
MAX_DATA = 512
NON_EXISTING_VHOST = "f00aa3a1775a0626"

def parse_http(vhost, raw):
    """ 
        parse_http returns a Tuple of (Result, ResultTuple).

        Result can be True or False
        ResultTuple
            contains the vhost, HTTP code, HTTP status 
            message, content length and possibly a 
            additional content location.

    """
    raw = [entry.strip() for entry in raw.split("\n")]
    try:
        version, code, status = raw[0].split(" ")
    except ValueError:
        return False, None
    if not version.startswith("HTTP"):
        return False, None
    length = 0
    content_location = ""
    for line in raw[1:]:
        try:
            key, value = line.split(":",1)
        except ValueError:
            continue
        value = value.strip()
        key = key.lower()
        if key == "content-length":
            length = str(int(value))
        elif key == "content-location":
            content_location = value
        elif key == "location" and ((content_location == "") or (code == "302")):
            content_location = value
    return True, (vhost, code, status, length, content_location,)

def connect_check(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((ip, port))
    except:
        return False
    s.close()
    return True

def http_get(ip, port, vhost, use_ssl=False):
    """ http_get queries a server for a given vhost. """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((ip, port))
    except:
        return False, None
    if use_ssl:
        # wrap socket for ssl thingy
        s = ssl.wrap_socket(s)
    try:
        s.sendall(REQUEST % (vhost))
    except:
        s.close()
        return False, None
    try:
        data = s.recv(MAX_DATA)
    except:
        s.close()
        return False, None
    try:
        s.close()
    except:
        pass
    return parse_http(vhost, data)

def output_thread(q):
    while True:
        print(";".join([str(val) for val in q.get()]))
        q.task_done()

def http_worker(ip, port, use_ssl, input_queue, output_queue, append):
    vhost = NON_EXISTING_VHOST
    if append != "":
       vhost += append
    res, data = http_get(ip, port, vhost, use_ssl)
    if res:
        _, non_code, non_status, non_length, non_content_location = data
    else:
        non_code = None
    while True:
        vhost = input_queue.get()
        if append != "":
            vhost += append
        res, data = http_get(ip, port, vhost, use_ssl)
        if res:
            _, code, status, length, content_location = data
            if non_code and (code == non_code) and (status == non_status) and (length == non_length) and (content_location == non_content_location):
                # seems to be a non-existing host
                pass
            else:
                output_queue.put(data)
        input_queue.task_done()

def set_up(host, ip, port, use_ssl, wordlist, threads, out_queue, append):
    in_queue = Queue()
    for entry in wordlist:
        in_queue.put(entry)
    for i in xrange(0,threads):
        t = Thread(target=http_worker, args=(ip, port, use_ssl, in_queue, out_queue, append,))
        t.daemon = True
        t.start()
    return True, in_queue

# Main
def main(argv):
    parser = argparse.ArgumentParser(description='Multi-threaded vhost enumeration tool.')
    parser.add_argument('hosts', metavar='HOST', type=str,
                        help='Target host name (e.g. "www.example.com" or "https://www.example.com" or "https://www.example.com:4433") to test.')
    parser.add_argument('--threads', dest='threads', type=int,
                        default=8,
                        help='VHOST resolver threads per host (default: 8)')
    parser.add_argument('--timeout', dest='timeout', type=int,
                        default=5.0,
                        help='DNS resolver timeout in seconds (default: 5)')
    parser.add_argument('--append', dest='append', type=str,
                        default="", metavar='.example.com',
                        help='append the string to the vhost (default: "")')
    parser.add_argument('--wordlist', dest='wordlist', 
                        default="dns-big.txt",
                        help='VHOST wordlist (default: dns-big.txt)')
    args = parser.parse_args()

    socket.setdefaulttimeout(args.timeout)

    # processing hosts
    print("[*] Parsing Hosts...")
    hosts = []
    args.hosts = [args.hosts]
    for entry in args.hosts:
        try:
            use_ssl = False
            port = 80
            if "://" in entry:
                protocol, seperator, domain = entry.partition("://")
                protocol = protocol.lower()
                domain = domain.lower()
                if not protocol.startswith("http"):
                    print("Wrong protocol: " + entry)
                    return False
                elif protocol == "https":
                    print("[X] HTTPS is *not working* at the moment! Sorry!!!")
                    return False
                    port = 443
                    use_ssl = True
                entry = domain
            if ":" in entry:
                domain, port = entry.split(":")
                port = int(port)
                if port == 0:
                    print("Wrong port: " + entry)
                    return False
                entry = domain
            try:
                ip = socket.gethostbyname(entry)
            except:
                print("Couldn't resolve host: " + entry)
                return False
            if not connect_check(ip, port):
                print("ConnectCheck failed: " + entry)
            print("[+] Alive: " + entry)
            hosts.append((entry, ip, port, use_ssl,))
        except:
            print("Error parsing host: " + entry)
            return False

    wordlist = os.path.join(SCRIPT_PATH, args.wordlist)
    if not os.path.isfile(wordlist):
        wordlist = args.wordlist
        if not os.path.isfile(wordlist):
            print("File not found: " + wordlist)
            return False

    start = int(time.time())
    print("[*] Loading Wordlist...")
    in_queue = Queue()
    out_queue = Queue()
    counter = 0
    with open(args.wordlist, 'r') as f:
        wordlist = []
        for line in f:
            line = line.strip()
            if line == "":
                continue
            wordlist.append(line)

    print("[*] Starting Output Thread...")
    t = Thread(target=output_thread, args=(out_queue,))
    t.daemon = True
    t.start()

    print("[*] Starting VHOST Threads...\n")
    queues = []
    for host, ip, port, use_ssl in hosts:
        res, queue = set_up(host, ip, port, use_ssl, wordlist, args.threads, out_queue, args.append)
        if not res:
            print("[X] Error.")
            return False
        queues.append(queue)

    for queue in queues:
        queue.join()
    out_queue.join()
    tick = int(time.time())-start
    counter = len(wordlist)*len(hosts)
    try:
        persec = counter/tick
    except ZeroDivisionError:
        persec = counter
    print("\n[X] Done (%d seconds for %d requests [%.2f/s])" % (tick, counter, persec))

    return True


if __name__ == "__main__":
    import sys
    print( __doc__ )
    sys.exit( not main( sys.argv ) )
