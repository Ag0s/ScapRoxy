#!/usr/bin/env python2.7

# requirements: apt-get install build-essential python-dev libnetfilter-queue-dev
# requirements: pip install NetfilterQueue

# Work in progress

from scapy.all import *
import sys, os, getopt, random, time
from netfilterqueue import *

# Global Variables
version = "v0.2"
verbose = False
evilBit = False
attackMode = 0
size = 53
proxy = ""

def head():
    print ''' _____                ______ _______   __
/  ___|               | ___ \  _  \ \ / /
\ `--.  ___ __ _ _ __ | |_/ / | | |\ V / _   _
 `--. \/ __/ _` | '_ \|    /| | | |/   \| | | |
/\__/ / (_| (_| | |_) | |\ \\\ \_/ / /^\ \ |_| |
\____/ \___\__,_| .__/\_| \_|\___/\/   \/\__, |
                | |                       __/ |
                |_|                      |___/ '''+version+"\n"

def usage():
    print "Usage: scapROXy.py -a 1 -s 500 -p 8080,3128"
    print
    print "-a n   --attack-mode=n        - Mode of attack"
    print "-e     --evil                 - Set the Evil bit"
    print "-h     --help                 - This usage screen"
    print "-v     --verbose              - Print verbose output"
    print "-s n   --packet-size=n        - Packet fragment size (Default: 53)"
    print "-p n   --proxy=n              - Add comma seperated ports to firewall rules"
    print
    print "Attack modes:"
    print "1 - Fragmented"
    print "2 - Fragmented and mixed (not yet working)"

    sys.exit(0)

def parse(packet):
    # Parse packet to be modified
    pkt = IP(packet.get_payload())
    tcppkt = TCP(packet.get_payload())

    ## Add packet modifiers here ##

    if evilBit:
#        if pkt[IP].flags == 2:
#            pkt[IP].flags = 6 #DF+evil
        pkt[IP].flags = pkt[IP].flags+4 # Adding Evil Flag
    if attackMode in (1, 2):
        del pkt[IP].chksum
        #del pkt[TCP].chksum
        fragmenter(pkt)
        # Fragmented packets get sent in fragmenter, so dropping from queue
        packet.drop()
    else:
        del pkt[IP].chksum
        #del pkt[TCP].chksum
        packet.set_payload(str(pkt))
        packet.accept()

def fragmenter(pkt):
    # Fragments packets and shuffles packet order
    fragments = fragment(pkt, fragsize=size)
    pnum = len(fragments)
    count = 1
    if attackMode == 2:
        fragments = random.shuffle(fragments)
    for frag in fragments:
        if verbose:
            print "Packet no# "+str(count)+"/"+str(pnum)
            print "============================================"
            frag.show()
        if pnum == count:
            sr(frag)
            count += 1
        else:
            send(frag)
            count += 1
    return

def main():
    # Main program
    global verbose
    global evilBit
    global attackMode
    global size
    global proxy

    if not len(sys.argv[1:]):
        head()
        usage()
    try:
        head()
        # Setting options, options with variables have a semicolon
        opts, args = getopt.getopt(sys.argv[1:], "a:s:evhp:", ["AttackMode","PacketSize","EvilBit","Verbose","Help","Proxy"])

    except getopt, GetoptError:
        print str(sys.exc_info())
    # Parsing option and variables
    for o, a in opts:
        if o in ("-a","--attack-mode"):
            attackMode = int(a)
            if attackMode in (1, 2):
                attackMode = attackMode # mock filler
            else:
                print "[!] Unkown attak mode \n"
                usage()
        elif o in ("-s","--packet-size"):
            size = int(a)
        elif o in ("-e","--evil"):
            evilBit = True
        elif o in ("-v", "--verbose"):
            verbose = True
        elif o in ("-h", "--help"):
            usage()
        elif o in ("-p", "--proxy"):
            proxy = ",",int(a)
        else:
            assert False, "Unhandled option"

    # IPTables rules to catch packets in queue
    print "[*] Setting up iptable rules\n"
    print "[!] Forwarding port 80"+proxy+" and 443"
    os.system("iptables -A OUTPUT -p tcp --match multiport --dport 80,443"+proxy+" -j NFQUEUE --queue-num 1")

    if verbose:
        # Printing verbose setting information
        print "\n[*] Settings"
        print "============================================"
        print "[+] Verbose mode set"
        if evilBit:
            print "[+] Evil bit will be set"
        if attackMode == 0:
            print "[-] No modifying attack mode set"
        if attackMode == 1:
            print "[+] Packet fragmentation mode set"
        if attackMode == 2:
            print "[+] Fragmented and mixed mode set"
        if attackMode > 0:
            print "[+] Packet size: "+str(size)

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, parse)
    try:
        nfqueue.run() #main loop

    except KeyboardInterrupt:
        # Cleanup on exception
        print "\n[!] Ctrl+C pressed"
#        time.sleep(0.5)
        nfqueue.unbind()
        print "[!] Sockets closed"
        os.system("iptables -D OUTPUT -p tcp --match multiport --dports 80,443"+proxy+" -j NFQUEUE --queue-num 1")
#        time.sleep(0.5)
        print "[!] Iptable rules removed"
#        time.sleep(1)
#        os.system("clear")
#        head()
        print "\n           *** Mischief managed ***\n"
        sys.exit(1)

if __name__ == '__main__':
    main()

