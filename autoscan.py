#!/usr/bin/env python

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


parser = argparse.ArgumentParser(description='Scan the network hosts under the default gateway or a specified interface using nmap with sane defaults.')
parser.add_argument('-i', '--interface', metavar='interface', default=get_default_interface(), type=str, nargs='?', help='Specify the interface to scan')
parser.add_argument('-d', '--discovery', metavar='discovery scan arguments', default='-sP -n', type=str, nargs='?', help='Nmap parameters for the discovery scan')
parser.add_argument('-s', '--service', metavar='service scan arguments', default='-sV -T4 -F', type=str, nargs='?', help='Nmap parameters for the service scan')
parser.add_argument('-a', '--address', metavar='address range', default='', type=str, nargs='?', help='Address range in the nmap format, ex. 192.168.0.0-255')
args = parser.parse_args()

interface = args.interface
discovery_args = args.discovery 
service_args = args.service 
address_range = args.address


def print_host_summary(address, open_ports):
    print('Host ' + address + ' has open ports: ' + str(open_ports))

def nmap_address_range(network):
    hosts = list(network.hosts())
    first = hosts[0].exploded.split('.')
    last = hosts[-1].exploded.split('.')
    address_range = ''
    for i in range(4):
        if last[i] == first[i]:
            address_range += '%s.' % first[i]
        else:
            address_range += '%s-%s.' % (first[i], last[i])
    return address_range[:-1]

def get_address_range(network):
    global address_range
    if address_range != '':
        return address_range
    else:
        return nmap_address_range(network)

def discovery_scan(network):
    result = nm.scan(hosts=get_address_range(network), arguments=discovery_args)
    hosts = list(result['scan'].keys()) 
    print('Hosts discovered:')
    for host in hosts:
        print(host)
    return hosts

def print_results():
    print()
    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s' % host)
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
    nm.scan(hosts=host_string, arguments=service_args)
    print_results()


print('Using interface ' + interface)
addresses = netifaces.ifaddresses(interface)

if interface not in netifaces.interfaces():
    print('Specified interface ' + interface + ' not found.')
    print('Available interfaces: ' + str(netifaces.interfaces()))
    exit(1)

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
    print('Initiating discovery scan on range: ' + get_address_range(network) + '...')
    discovered_hosts = discovery_scan(network)
    print()
    print('Initiating service scan on ' + str(len(discovered_hosts)) + ' discovered hosts, this can take a while...')
    service_scan(discovered_hosts)
    print()
    print('Scan done in ' + str(int(round(time.time() - t0))) + ' seconds')
except KeyboardInterrupt:
    print('Aborted!')
    sys.exit()



