import sys
import argparse
import logging
import adenum

logger = logging.getLogger(adenum.__name__)

parser = argparse.ArgumentParser()
parser.add_argument('-d', '--domain', help='domain')
parser.add_argument('--debug', action='store_true', help='enable debug output')
parser.add_argument('-n', '--name-server', dest='name_server', help='name server')
args = parser.parse_args()
if args.debug:
    logger.setLevel(logging.DEBUG)
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter('[%(levelname)s]:%(lineno)s %(message)s'))
    logger.addHandler(h)

if not args.domain:
    if args.name_server:
        name = get_fqdn_by_addr(args.name_server, args.name_server)
        if name:
            args.domain = name.split('.', maxsplit=1)[-1]

if not args.domain:
    print('Error: must specify a domain')

for addr in adenum.get_domain_controllers(args.domain, args.name_server):
    name = adenum.get_fqdn_by_addr(addr, args.name_server)
    if name:
        print(addr, '\t', name)
    else:
        print(addr)
