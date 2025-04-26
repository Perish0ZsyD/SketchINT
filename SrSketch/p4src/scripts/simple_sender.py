#!/usr/bin/env python
import sys
import socket
import random
import time
import argparse
from subprocess import Popen, PIPE
import re
from threading import Thread, Event
from scapy.all import *
from p4utils.utils.topology import Topology



class SourceRoute(Packet):
    field_desc = [ BitField("bos", 0, 1),
                   BitField("port", 0, 15)]
    



class MIH(Packet):
    name="MIH"
    #bitfiled(<name>,<default>,<length>)
    fields_desc=[\
            BitField("mih_switch_id",0,16),\
            BitField("mih_timestamp",0,48),\
            BitField("mih_padding",0,16),\
            BitField("sfh_exists_fg",0,8)]

class flag(Packet):
    name="flag"
    fields_desc=[\
            BitField("mih_switch_id",0,8)]
    

#always via eth0
def get_if():
    ifs=get_if_list()
    iface=None  # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


def get_dst_mac(ip):
    try:
        pid = Popen(["arp", "-n", ip], stdout=PIPE)
        s = pid.communicate()[0]
        mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
        return mac
    except:
        return None

def SwitchConfig(Packet):

    



def main():
    
    if len(sys.argv) < 3:
        print("pass 2 arguments: <dst host ip address> <number of packets>")
        exit(1)

    
    parser=argparse.ArgumentParser()
    parser.add_argument("d",help="the dst host name")
    parser.add_argument("p",help="the program to be run",choices=["f","i"])

    parser.add_argument("-t","--type",help="the packet type to be sent",default="udp",choices=["udp","tcp","icmp"])
    parser.add_argument("-n","--number",help="the packet number to be sent",type=int,default=1)
    args=parser.parse_args()

    interface=get_if()
    send_packet(interface,args,args.p)

if __name__ == "__main__":
    main()
