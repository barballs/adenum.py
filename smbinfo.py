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
        s =  'Address:       {}\n'.format(addr)
        s += 'Negotiated:    {}\n'.format(info['smbNegotiated'])
        s += 'Build:         {}\n'.format(info.get('build', ''))
        s += 'NativeOS:      {}\n'.format(info.get('native_os', ''))
        s += 'NativeLM:      {}\n'.format(info.get('native_lm', ''))
        s += 'Available:     {}\n'.format(info['smbVersions'])
        if args.uptime or args.all:
            s += 'Uptime:        {}\n'.format(info.get('uptime', ''))
            s += 'Date:          {}\n'.format(info.get('date', ''))
        if args.domain or args.all:
            s += 'AuthContext:   {}\n'.format(info['auth_context'])
            s += 'DnsDomain:     {}\n'.format(info['dns_domain'])
            s += 'DnsName:       {}\n'.format(info['dns_name'])
            s += 'NetBIOSDomain: {}\n'.format(info['netbios_domain'])
            s += 'NetBIOSName:   {}\n'.format(info['netbios_name'])
        s += os.linesep
        sys.stdout.write(s)

parser = argparse.ArgumentParser()
parser.add_argument('hosts', nargs='*', default=[], help='addresses to scan')
parser.add_argument('-c', '--csv', action='store_true', help='output in CSV')
parser.add_argument('-d', '--domain', action='store_true', help='get domain/workgroup info')
parser.add_argument('-a', '--all', action='store_true', help='get all information possible')
parser.add_argument('-u', '--uptime', action='store_true', help='report uptime. SMB2 only')
parser.add_argument('-x', '--nmap', help='nmap xml file. checks for open 445')
parser.add_argument('-t', '--timeout', type=float, default=2, help='socket timeout in seconds')
parser.add_argument('--threads', type=int, default=50, help='worker threads count. defaults to 50')
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
get_smb_info_thread(list(hosts)[0], args)
sys.exit()
with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as e:
    concurrent.futures.wait([e.submit(get_smb_info_thread, h, args) for h in set(hosts)])
