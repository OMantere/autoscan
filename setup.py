from setuptools import setup, find_packages

setup(name='autoscan',
        version='0.0.1',
        description='Scan hosts under the default interface or a specified one using nmap with sane defaults',
        package='autoscan',
        install_requires=['netifaces', 'python-nmap', 'ipaddress'])
