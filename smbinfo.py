import os
import sys
import time
import socket
import struct
import argparse
import binascii
import datetime
import concurrent.futures
import threading
import xml.etree.ElementTree as ET

from adenum import get_smb_info

def get_smb_info_thread(addr, args):
    info = get_smb_info(addr, args.timeout)
    if args.csv:
        sys.stdout.write(','.join([
            addr, str(info['smbNegotiated']), info.get('native_os', ''),
            info.get('native_lm', ''), info['smbVersions'].replace(', ', '/')
        ])+os.linesep)
    else:
        s =  'Address:   {}\n'.format(addr)
        s += 'Version:   {}\n'.format(info['smbNegotiated'])
        s += 'Build:     {}\n'.format(info.get('build', ''))
        s += 'NativeOS:  {}\n'.format(info.get('native_os', ''))
        s += 'NativeLM:  {}\n'.format(info.get('native_lm', ''))
        s += 'Available: {}\n'.format(info['smbVersions'])
        s += os.linesep
        sys.stdout.write(s)

parser = argparse.ArgumentParser()
parser.add_argument('hosts', nargs='*', default=[], help='addresses to scan')
parser.add_argument('-c', '--csv', action='store_true', help='output in CSV')
parser.add_argument('-x', '--nmap', help='nmap xml file')
parser.add_argument('-t', '--timeout', type=float, default=2, help='socket timeout in seconds')
args = parser.parse_args()
hosts = set(args.hosts)
if args.nmap:
    scan = ET.parse(args.nmap).getroot()
    if not scan.tag == 'nmaprun':
        raise ValueError('file is not nmap xml')
    for host in scan.findall('./host'):
        ports = [int(p.get('portid')) for p in host.findall('./ports/port') if p.find('state').get('state') == 'open']
        if 445 in ports:
            hosts.add([e.get('addr') for e in host.findall('./address') if e.get('addrtype') == 'ipv4'][0])
if args.csv:
    print('host', 'smbNegotiated', 'native_os', 'native_lm', 'smbVersions', sep=',')
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as e:
    concurrent.futures.wait([e.submit(get_smb_info_thread, h, args) for h in set(hosts)])
