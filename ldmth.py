#!/bin/python3
####################
# ejcSec           #
# Loudmouth        #
####################
import logging

logger = logging.getLogger('script_logger')
logger.setLevel(logging.DEBUG)
# create file handler which logs even debug messages
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.ERROR)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
ch.setFormatter(formatter)
# add the handlers to logger
logger.addHandler(ch)

import argparse, sys,socket
from scapy.all import *
import ipaddress
import psutil
import math

#vars
interface_list = get_if_list()

def asciibanner():
    print("""
    #                            #     #
    #        ####  #    # #####  ##   ##  ####  #    # ##### #    #
    #       #    # #    # #    # # # # # #    # #    #   #   #    #
    #       #    # #    # #    # #  #  # #    # #    #   #   ######
    #       #    # #    # #    # #     # #    # #    #   #   #    #
    #       #    # #    # #    # #     # #    # #    #   #   #    #
    #######  ####   ####  #####  #     #  ####   ####    #   #    #
    """)

def arpflood(interface, pkt_count):
    print("Initializing ARP flood...")
    ip = get_if_addr(interface)
    # create an ARP request to flood the network with
    send(Ether('ff:ff:ff:ff:ff:ff')/ARP(op="who-has",pdst = ip), count = pkt_count)

def pingflood(interface, pkt_count, range):
    print("Initializing ping flood...")
    ip = get_if_addr(interface)
    if range:
        send(IP(dst = ip  + "/" + range, proto=(0,255))/"LoudMouth",iface = interface, count = pkt_count)
    else:
        send(IP(dst = ip, proto=(0,255))/"LoudMouth",iface = interface, count = pkt_count)

def tcpflood(interface, pkt_count, range):
    print("Initializing TCP flood...")
    ip = get_if_addr(interface)
    # generate ACK packaets
    if range:
        send(IP(dst = ip + "/" + range)/TCP(dport=[80,8080],flags="A")/Raw("A"*1024), count = pkt_count)
    else:
        send(IP(dst = ip)/TCP(dport=[80,8080],flags="A")/Raw("A"*1024), count = pkt_count)

def udpflood(interface, pkt_count, range):
    print("inititalizing UDP flood...")
    ip = get_if_addr(interface)
    if mask:
        send(IP(dst = ip + "/" + range)/UDP(dport=[80,333],flags="P")/RAW("U"*1024),count = pkt_count)
    else:
        send(IP(dst = ip)/UDP(dport=[80,333],flags="P")/RAW("U"*1024),count = pkt_count)
# carries out all packet floods one at a time
def allflood(interface, pkt_count, range,  duration):
    print("All floods will be initiated!")

def main():
    asciibanner()
    parser = argparse.ArgumentParser(description = 'Process user input')
    parser.add_argument('-m','--mode', choices  =  ['arp','tcp','ping','all'], help = 'The flooding mode that loudmouth will utilize')
    parser.add_argument('-i','--interface',type  = str, help = 'The network interface that loudmouth will target (default = first interface found)',choices = interface_list, default = interface_list[0])
    parser.add_argument('-v','--verbose',action = 'store_true', help = 'Instructs loudmouth to print our more output')
    parser.add_argument('-p','--packetcount',type = int, help = 'How many packets loudmouth will send (default = 10 packets)',default = 10)
    parser.add_argument('-r','--range', type = str, help = 'Range of IPs to send packets to')
    args = parser.parse_args()
    interface = args.interface
    pktcount = args.packetcount
    range = args.range

    if args.mode:
        chosen_flood  = args.mode
        if chosen_flood == 'arp':
            arpflood(interface, pktcount)
        elif chosen_flood  == 'tcp':
            tcpflood(interface, pktcount, range)
        elif chosen_flood == 'ping':
            pingflood(interface, pktcount,range)
        elif chosen_flood == 'udp':
            udpflood(interface, pktcount,range)
        elif chosen_flood == 'all':
            allflood()

if __name__ == "__main__":
    main()
