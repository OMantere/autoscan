#!/usr/bin/python

import socket
import argparse
import netifaces
import os
import ipaddress
import time
import sys
from scapy.all import *


def get_default_interface():
    return netifaces.gateways()['default'][netifaces.AF_INET][1]

def get_default_gateway():
    return netifaces.gateways()['default'][netifaces.AF_INET][0]

port_range = range(1, 100)

def scan_host(address):
    src_port = 1337
    open_ports = []
    for port in port_range:  
        tcp_connect_scan_resp = sr1(IP(dst=address)/TCP(sport=src_port,dport=port,flags="S"),timeout=10)
        if (tcp_connect_scan_resp.haslayer(TCP)) or (tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=address)/TCP(sport=src_port,dport=port,flags="AR"),timeout=10)
            open_ports.append(port)
    return open_ports

def print_host_summary(address, open_ports):
    print('Host ' + address + ' has open ports: ' + str(open_ports))

parser = argparse.ArgumentParser(description='Scan the network for hosts under the default gateway or a specified interface.')
parser.add_argument('-i', '--interface', metavar='interface', default=get_default_interface(), type=str, nargs='?', help='Specify the interface to scan')
args = parser.parse_args()

interface = args.interface

if interface not in netifaces.interfaces():
    print('Specified interface ' + interface + ' not found.')
    print('Available interfaces: ' + str(netifaces.interfaces()))
    exit(1)

print('Using interface ' + interface)

addresses = netifaces.ifaddresses(interface)

if netifaces.AF_INET not in addresses:
    print('ERROR: Interface does not have an IPv4 address')
    exit(1)

if len(addresses[netifaces.AF_INET]) != 1:
    print('ERROR: Interface has ' + str(len(addresses)) + ' IPv4 addresses, should have 1')
    exit(1)

ipv4_address = addresses[netifaces.AF_INET][0]

if 'netmask' not in ipv4_address:
    print('ERROR: Could not get network mask')
    exit(1)

default_gateway = get_default_gateway()
netmask = ipv4_address['netmask']

print('Default gateway: ' + default_gateway + ', Network mask: ' + netmask)

network = ipaddress.IPv4Network((default_gateway, netmask), strict=False)
print('Scanning ' + str(network.num_addresses) + ' hosts')


# Scanning
t0 = time.time()

try:
    for host in network.hosts():
        address = host.exploded
        print('Scanning host ' + address)
        open_ports = scan_host(address)
        if len(open_ports) > 0:
            print_host_summary(address, open_ports)
        else:
            print('Host ' + address + ' is down')
except KeyboardInterrupt:
    sys.exit()

print('Scan done in ' + str(int(round(time.time() - t0))) + ' seconds')


