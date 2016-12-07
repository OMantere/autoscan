from setuptools import setup, find_packages

setup(name='netscan',
        version='0.0.1',
        description='Scan for hosts under the default interface or a specified one',
        package='netscan',
        install_requires=['netifaces', 'scapy'])
