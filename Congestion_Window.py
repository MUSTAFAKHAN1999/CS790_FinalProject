import sys
import getopt
import time
import math
from os import popen
import logging
from scapy.all import sendp, IP, UDP, Ether, TCP, sniff
from random import randrange

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

""" Python Program to instigate, detect and mitigate DDoS Attack """

"""
 main function to start the DDoS attack,
 It first sends normal traffic, then sends attack traffic,
 then sends normal traffic again to simulate real world traffic
"""


def main(argv):
    # open interface eth0 to send packets
    interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()

    """ 
    Store packet information in two dictionaries called map1 and map2
     map1 has MAC address as key and port num, switch and set of IP's generated from
     that MAC address as values
     map2 has destination IP address as key and the no of packets received from that IP as valaue,
     to keep track of packets sent, we have two variables freq and freq2
     We also set an initial Entropy of 0.8
     We do this all in a congestion window of size 50
    """
    congestion_window_size = 50
    sent_packets = 0
    ip_addr = set()
    map1 = {}
    map2 = {}
    freq = 0
    freq2 = 0
    INIITIAL_ENTROPY = 0.8
    calculated_entropy = 0

    # generate and send 100 normal packets from 2 sources
    for i in range(100):
        if sent_packets < congestion_window_size:
            packets = Ether() / IP(dst="10.0.0.1", src="10.0.0.4") / TCP(dport=80, sport=2)
            freq = freq + 1
            ip_addr.add(str(packets[IP].src))
            map2[str(packets[IP].dst)] = freq

            packets2 = Ether() / IP(dst="10.0.0.2", src="10.0.0.4") / TCP(dport=80, sport=2)
            freq2 = freq2 + 1
            ip_addr.add(str(packets2[IP].src))
            # Add relevant information to mmap1 and map2
            map2[str(packets2[IP].dst)] = freq
            map1[str(Ether().src)] = {'in-port': 2, 'in-switch': 's2', 'ip': ip_addr}

            sendp(packets, iface=interface.rstrip(), inter=0.1)
            sent_packets += 1

            # calculate entropy by calling the entropy function
            calculated_entropy = entropy(map1, map2)
            print(calculated_entropy)

        else:
            # reset the congestion window to size 50 once its full
            time.sleep(1)
            congestion_window_size = 50
            sent_packets = 0

    #  sending attack data
    for i in range(2000):
        if sent_packets < congestion_window_size:
            packets = Ether() / IP(dst="10.0.0.1", src="10.0.0.3") / TCP(dport=80, sport=2)
            freq = freq + 1
            ip_addr.add(str(packets[IP].src))
            map2[str(packets[IP].dst)] = freq
            map1[str(Ether().src)] = {'in-port': 2, 'in-switch': 's2', 'ip': ip_addr}

            calculated_entropy = entropy(map1, map2)
            print(calculated_entropy)

            # check if entropy of network is less than initial entropy
            # if less, check if DDoS or not by calling the checkDDoS method
            # if DDoS found, packet dropped, else packet sent
            if calculated_entropy < INIITIAL_ENTROPY:
                print("----------High Traffic Detected----------")
                print("----------Checking for DDoS--------------")
                x = checkDDoS(map1)

                if x == True:
                    print("-------------Packet Dropped-----------")
                else:
                    print("-------------Flash Crowd-----------")
                    sendp(packets, iface=interface.rstrip(), inter=0.025)
                    sent_packets += 1

            else:
                # send packet regularly if network entropy more than initial entropy
                sendp(packets, iface=interface.rstrip(), inter=0.025)
                sent_packets += 1



        else:
            # reset congestion window
            time.sleep(1)
            congestion_window_size = 50
            sent_packets = 0

    # send normal traffic again
    for i in range(100):
        if sent_packets < congestion_window_size:
            packets = Ether() / IP(dst="10.0.0.1", src="10.0.0.4") / TCP(dport=80, sport=2)
            freq = freq + 1
            ip_addr.add(str(packets[IP].src))
            map2[str(packets[IP].dst)] = freq

            packets2 = Ether() / IP(dst="10.0.0.2", src="10.0.0.4") / TCP(dport=80, sport=2)
            freq2 = freq2 + 1
            ip_addr.add(str(packets2[IP].src))
            map2[str(packets2[IP].dst)] = freq

            map1[str(Ether().src)] = {'in-port': 2, 'in-switch': 's2', 'ip': ip_addr}

            calculated_entropy = entropy(map1, map2)
            print(calculated_entropy)

            sendp(packets, iface=interface.rstrip(), inter=0.1)
            sent_packets += 1



        else:
            time.sleep(1)
            congestion_window_size = 50
            sent_packets = 0


""" 
This function  is used to calculate network entropy, it takes 2 arguments
map1 - the map 1 dictionary we calculated while sending packets
map2 - the map 2 dictionary we calculated while sending packets
It uses the mathematical formula of entropy to calculate it and returns it
"""


def entropy(map1, map2):
    total_packets = 0
    x = list(map2.keys())
    # counting total packets
    for i in range(len(x)):
        total_packets = total_packets + map2[x[i]]

    # calculating  probabilities
    prob1 = map2[x[0]] / total_packets
    prob2 = map2[x[1]] / total_packets

    # calculating network entropy
    entropy_network = -prob1 * math.log2(prob1) - prob2 * math.log2(prob2)

    print()
    print("\nTotal Packets are :" + str(total_packets))
    return entropy_network


""" 
This function  is used to check weather the network is under a DDoS attack
or extremely heavy traffic. This done by checking the IP addresses coming from a MAC address
Each machine has 1 unique MAC address and if it sends packets from more than 1 IP address, we
identify it as DDoS attack.
It takes in 1 parameter, the map1 dictionary
"""


def checkDDoS(mp):
    key = list(mp.keys())
    ip_set = len(mp.get(key[0])['ip'])

    # print(ip_set)

    if ip_set > 1:
        print("----------------DDoS DETECTED ----------------")
        print("Stopping All Traffic from: " + key[0])
        return True

    else:
        print("--------------------NO DDoS--Flash Crowd---------------------")
        return False


if __name__ == '__main__':
    main(sys.argv)
