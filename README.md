# Autoscan

Tries to automatically detect your default gateway/network interface and do a port scan on the host space of the local network using nmap with sane defaults. Optionally provide your own interface of choice, and/or parameters for nmap to use in the discovery and service scans, respectively.

## Install

Run `python setup.py install` in the project directory.

## Usage

~~~~
usage: autoscan.py [-h] [-i [interface]] [-d [discovery scan arguments]]
                   [-s [service scan arguments]]

Scan the network hosts under the default gateway or a specified interface
using nmap with sane defaults.

optional arguments:
  -h, --help            show this help message and exit
  -i [interface], --interface [interface]
                        Specify the interface to scan
  -d [discovery scan arguments], --discovery [discovery scan arguments]
                        Nmap parameters for the discovery scan
  -s [service scan arguments], --service [service scan arguments]
                        Nmap parameters for the service scan
~~~~
