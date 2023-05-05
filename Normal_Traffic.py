import sys
import getopt
import time
from os import popen
import logging
from scapy.all import sendp, IP, UDP, Ether, TCP
from random import randrange

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

""" Python Program to Generate Regular TCP Traffic """

""" 
This function  is used to generate regular traffic, it takes 2 arguments,
source: The source IP which will generate traffic
destination: The destination IP which will receive traffic
"""


def main(src, dst):
    # open interface eth0 to send packets
    interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()

    # use for-loop to generate and send  1000 packets
    for i in range(1000):
        packets = Ether() / IP(dst=dst, src=src) / TCP(dport=80, sport=2)
        sendp(packets, iface=interface.rstrip(), inter=0.1)


# call the main function and pass the parameters from the user
if __name__ == '__main__':
    source = str(input("Enter Source IP : "))
    destination = str(input("Enter Destination IP : "))
    main(source, destination)
