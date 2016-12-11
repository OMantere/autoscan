#!/usr/bin/python

import socket
import argparse
import netifaces
import os
import ipaddress
import time
import sys
import nmap

nm = nmap.PortScanner()


def get_default_interface():
    return netifaces.gateways()['default'][netifaces.AF_INET][1]

def get_default_gateway():
    return netifaces.gateways()['default'][netifaces.AF_INET][0]

def print_host_summary(address, open_ports):
    print('Host ' + address + ' has open ports: ' + str(open_ports))

def discovery_scan(network):
    result = nm.scan(hosts='10.37.38.57', arguments='-sP')
    hosts = list(result['scan'].keys()) 
    print('Hosts discovered:')
    for host in hosts:
        print(host)
    return hosts

def print_results():
    print()
    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)

            lport = list(nm[host][proto].keys())
            lport.sort()
            for port in lport:
                port_info = nm[host][proto][port]
                info_string = 'port : %s\tstate : %s\tname: %s' % (port, port_info['state'], port_info['name'])
                if len(port_info['version']) > 0:
                    info_string += '\tversion: ' + port_info['version']
                print (info_string)


def service_scan(hosts):
    host_string = ' '.join(hosts)
    nm.scan(hosts=host_string, arguments='-A')
    print_results()


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
network = ipaddress.IPv4Network((default_gateway, netmask), strict=False)
print('Default gateway: ' + default_gateway + ', Network mask: ' + netmask)
print('We are ' + ipv4_address['addr'])


# Scanning
t0 = time.time()

try:
    print()
    print('Initiating discovery scan on ' + str(network.num_addresses) + ' addresses...')
    discovered_hosts = discovery_scan(network)
    print()
    print('Initiating service scan on ' + str(len(discovered_hosts)) + ' discovered hosts, this can take a while...')
    service_scan(discovered_hosts)
    print()
    print('Scan done in ' + str(int(round(time.time() - t0))) + ' seconds')
except KeyboardInterrupt:
    print('Aborted!')
    sys.exit()



