#!/bin/python3
#Author: Michael Rodman

'''
Must be ran as sudo since you are changing your IP address to match
a specific host that needs to be predefined.
'''

import os
import sys
import subprocess
import ipaddress
from scapy.all import *

#Defining host and packet size
host = '10.211.55.25' #IP of target
packet_size = '56'
interface = "enp0s3" #Interface that will act as target.
protocol_ports_tcp = [21, 25, 80]
protocol_names_tcp = ['ftp', 'smtp', 'http']
protocol_ports_udp = [123]
protocol_names_udp = ['ntp']

#Checking if host is reachable via ping
def ping_check(host):
    response_check = ping_check(host)

    if response_check == False:
        return False
    else:
        return True

print (ping_check(host))

#Sending continous pings to host at normal speed and size.
def ping_send(host):
    response_to_ping = os.system('ping -s ' +packet_size +' ' + host)

    if response_to_ping == 1:
        return True
    else:
        return False

print (ping_send(host))

#Creating larger packets to incorporate into ping_send.
def create_larger_packets():
    while True:
        packet_size_changed = packet_size +.001

        if (packet_size_changed == 512.001):
            break

'''
TO DO LATER
#Incorporating larger ICMP packets into pings.
def amplify_ping():
    while (ping_send(host) == true):
'''

#Changing the IP of the Rouge NIC to emulate the target machine.
def change_ip():
    os.system('ip link set dev ' + interface + ' down;\
            ip addr add '+ host + '/24 dev '+ interface';'\
            'ip link set dev '+ interface + 'up')


#Check for when the host is "unreachable" and calling for the IP change.
if (ping_check(host) == "False"):
    change_ip()