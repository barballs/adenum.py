import sys
import os
import struct
import argparse
import socket
import binascii
import configparser
import logging
import hashlib
import ssl
import subprocess
import getpass
import hashlib
import datetime
import tempfile
import concurrent.futures
# non-std
import ldap3
import dns.resolver
# NOTE: pysmb is imported on demand

DESCRIPTION = 'Enumerate ActiveDirectory users, groups, computers, and password policies'

'''
= SUMMARY =

This script is basically a python implementation of the windows "net" command.
It provides enumeration of users, groups, and password policies by performing
LDAP queries against an Active Directory domain controller.

= INSTALLATION =

You'll need to install ldap3 and dnspython:
    pip3 install ldap3 dnspython

You will also need either smbclient or pysmb to read the default password policy
from the SYSVOL share.

= EXAMPLES =

NOTE: If your system is not configured to use the name server for
the domain, you must specify the domain controller with -s or the
domain's name server with --name-server. In nearly all AD domains,
the domain controller acts as the name server. Domains specified
with -d must be fully qualified.

List password policies. Non-default policies may require higher privileges.
    python3 adenum.py -u USER -P -d mydomain.local policy

List all users and groups
    python3 adenum.py -u USER -P -d mydomain.local users
    python3 adenum.py -u USER -P -d mydomain.local groups

List domain admins
    python3 adenum.py -u USER -P -d mydomain.local group "domain admins"

List domain joined computers. Add -r and -u to resolve hostnames and get uptime (SMB2 only).
    python3 adenum.py -u USER -P -d mydomain.local computers

= TODO =
Find a better workaround for AD 1000 results limit.
OS fingerprinting limited to SMB1 hosts, use NTLM auth to get
OS info.

= RESOURCES =

all defined AD attributes
https://msdn.microsoft.com/en-us/library/ms675090(v=vs.85).aspx
'''

logger = logging.getLogger(__name__)
GTIMEOUT = 2

def get_smb_info(addr, timeout=GTIMEOUT):
    info = {'smbVersions':set()}
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((addr, 445))
    except Exception:
        return None

    # send SMB1 NegotiateProtocolRequest with SMB2 dialects. will lead to SMB2
    # negotiation even if SMB1 is disabled.
    s.send(binascii.unhexlify(
        b'000000d4ff534d4272000000001843c80000000000000000000000000000'
        b'feff0000000000b100025043204e4554574f524b2050524f4752414d2031'
        b'2e3000024d4943524f534f4654204e4554574f524b5320312e303300024d'
        b'4943524f534f4654204e4554574f524b5320332e3000024c414e4d414e31'
        b'2e3000024c4d312e32583030320002444f53204c414e4d414e322e310002'
        b'4c414e4d414e322e31000253616d626100024e54204c414e4d414e20312e'
        b'3000024e54204c4d20302e31320002534d4220322e3030320002534d4220'
        b'322e3f3f3f00'
    ))
    try:
        data = s.recv(4096)
    except ConnectionResetError:
        return None

    if data[4] == 0xff:
        dialects = ['PC NETWORK PROGRAM 1.0', 'MICROSOFT NETWORKS 1.03', 'MICROSOFT NETWORKS 3.0',
                    'LANMAN1.0', 'LM1.2X002', 'DOS LANMAN2.1', 'LANMAN2.1', 'Samba', 'NT LANMAN 1.0',
                    'NT LM 0.12']
        info['smbNegotiated'] = dialects[struct.unpack('<H', data[37:39])[0]]
    else:
        dialect = struct.unpack('<H', data[0x48:0x4a])[0]
        boottime = datetime.datetime.fromtimestamp((struct.unpack('<Q', data[0x74:0x7c])[0] / 10000000) - 11644473600)
        info['smbVersions'].add(2)
        info['uptime'] = str(datetime.datetime.now() - boottime) + ' (booted '+ \
                           boottime.strftime('%H:%M:%S %d %b %Y')+')'
        if dialect == 0x2ff:
            # send SMB2 NegotiateProtocolRequest with random client GUID and salt
            s.send(binascii.unhexlify(
                b'000000b6fe534d4240000000000000000000000000000000000000000100'
                b'000000000000000000000000000000000000000000000000000000000000'
                b'000000000000000024000800010000007f000000') + os.urandom(16) + \
                binascii.unhexlify(
                    b'780000000200000002021002220224020003020310031103000000000100'
                    b'260000000000010020000100') + os.urandom(32) + \
                binascii.unhexlify(b'00000200060000000000020001000200')
            )
            data = s.recv(4096)
            dialect = struct.unpack('<H', data[0x48:0x4a])[0]
            if dialect >= 0x300:
                info['smbVersions'].add(3)
        s.shutdown(socket.SHUT_RDWR)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((addr, 445))
        # send SMB1 NegotiateProtocolRequest with SMB1 dialects only
        s.send(binascii.unhexlify(
            b'000000beff534d4272000000001843c80000000000000000000000000000'
            b'feff00000000009b00025043204e4554574f524b2050524f4752414d2031'
            b'2e3000024d4943524f534f4654204e4554574f524b5320312e303300024d'
            b'4943524f534f4654204e4554574f524b5320332e3000024c414e4d414e31'
            b'2e3000024c4d312e32583030320002444f53204c414e4d414e322e310002'
            b'4c414e4d414e322e31000253616d626100024e54204c414e4d414e20312e'
            b'3000024e54204c4d20302e313200'
        ))
        info['smbNegotiated'] = hex(dialect)
        logger.debug('MaxSMBVersion: '+hex(dialect))
        try:
            s.recv(4096)
        except ConnectionResetError:
            s = None

    if s:
        # SMB1 SessionSetup with random PID
        s.send(
            binascii.unhexlify(
                b'0000009cff534d4273000000001843c800004253525350594c200000ffff') + \
            os.urandom(2) + \
            binascii.unhexlify(
                b'000001000cff000000ffff02000100000000004a000000000054c0008061'
                b'00604806062b0601050502a03e303ca00e300c060a2b0601040182370202'
                b'0aa22a04284e544c4d535350000100000015820862000000002800000000'
                b'00000028000000060100000000000f0055006e0069007800000053006100'
                b'6d00620061000000')
        )
        data = s.recv(4096)
        size = struct.unpack('<H', data[43:45])[0]
        native_os, native_lm = data[47+size:].split(b'\x00\x00\x00', maxsplit=1)
        native_os += b'\x00'
        native_lm = native_lm[:-2]
        info['native_os'] = native_os.decode('utf-16-le')
        info['native_lm'] = native_lm.decode('utf-16-le')
        info['smbVersions'].add(1)
        s.shutdown(socket.SHUT_RDWR)
    info['smbVersions'] = ', '.join(map(str, info['smbVersions']))
    return info

def get_uptime(addr, timeout=GTIMEOUT):
    ''' Return uptime string for SMB2+ hosts. Sends a SMB1 NegotiateProtocolRequest
    to elicit an SMB2 NegotiateProtocolRequest. Works even if SMB1 is disabled on
    the remote host. '''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((addr, 445))
    except Exception:
        return None
    s.send(binascii.unhexlify(
        b'00000039ff534d4272000000001843c80000000000000000000000000000f'
        b'eff0000000000160002534d4220322e3030320002534d4220322e3f3f3f00'
    ))
    data = s.recv(0x7d)
    s.shutdown(socket.SHUT_RDWR)
    if data[4] != 0xfe:
        return None
    logger.debug(addr+' SMB2 Dialect '+hex(struct.unpack('<H', data[0x48:0x4a])[0]))
    boottime = datetime.datetime.fromtimestamp((struct.unpack('<Q', data[0x74:0x7c])[0] / 10000000) - 11644473600)
    return str(datetime.datetime.now() - boottime) + ' (booted '+boottime.strftime('%H:%M:%S %d %b %Y')+')'


class CachingConnection(ldap3.Connection):
    ''' Subclass of ldap3.Connection which uses the range attribute
    to gather all results. It will also cache searches. '''
    def __init__(self, *args, **kwargs):
        self.cache = {}
        kwargs['auto_range'] = True
        ldap3.Connection.__init__(self, *args, **kwargs)
    def search(self, search_base, search_filter, search_scope=ldap3.SUBTREE, **kwargs):
        if 'attributes' not in kwargs:
            kwargs['attributes'] = []
        #kwargs['paged_size'] = 1000
        #kwargs['paged_criticality'] = True

        sha1 = hashlib.new('sha1', b''.join(
            str(a).lower().encode() for a in [search_base, search_filter]+list(kwargs.values()))).digest()
        if sha1 in self.cache:
            logger.debug('CACHE HIT')
            self.response = self.cache[sha1]
            return
        logger.debug('SEARCH ({}) {} {} ATTRS {}'.format(search_base, search_filter, search_scope,
                                                      ', '.join(kwargs['attributes'])))
        response = []
        super().search(
            search_base,
            search_filter,
            search_scope,
            **kwargs
        )
        # return only the results
        for obj in self.response:
            if obj['type'].lower() == 'searchresentry':
                for a in [a for a in obj['attributes'] if a.startswith('member;range=')]:
                    del obj['attributes'][a]
                response.append(obj)
        # try:
        #     cookie = self.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        # except KeyError:
        #     break
        # kwargs['paged_cookie'] = cookie

        self.response = response
        logger.debug('RESULT '+str(self.result))
        logger.debug('COUNT '+str(len(self.response)))
        self.cache[sha1] = self.response
            
        # if self.result['result'] == 4:
        #     kwargs['attributes'].append('range=1000-*')
        #     self.response += self.search(search_base, search_filter, search_scope=ldap3.SUBTREE, **kwargs)
        #     return self.response
        
private_addrs = (
    [2130706432, 4278190080], # 127.0.0.0,   255.0.0.0
    [3232235520, 4294901760], # 192.168.0.0, 255.255.0.0
    [2886729728, 4293918720], # 172.16.0.0,  255.240.0.0
    [167772160,  4278190080], # 10.0.0.0,    255.0.0.0
) 

def is_private_addr(addr):
    addr = int.from_bytes(socket.inet_aton(addr), 'big')
    for a in private_addrs:
        if (addr & a[1]) == a[0]:
            return True
    return False

def is_addr(a):
    try:
        socket.inet_aton(a)
    except:
        return False
    return True

def get_attr(o, attr, default=None, trans=None):
    ''' given a dict object returned by ldap, return the first named attribute or if it
    does not exists, return default '''
    if not o.get('attributes', None):
        return default
    v = o['attributes'].get(attr, None)
    if not v:
        return default
    if type(v) == list:
        if len(v) == 0:
            return default
        v = v[0]
    if trans:
        return trans(v)
    return v

def get_resolver(name_server=None, timeout=GTIMEOUT):
    if name_server:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [name_server]
    else:
        # use nameserver configured for the host
        resolver = dns.resolver
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver

def get_dc(domain, name_server=None):
    ''' return the domain controller for a given domain '''
    resolver = get_resolver(name_server)
    logger.debug('Resolving _ldap._tcp.'+domain)
    try:
        # first, try a DNS service query
        answer = resolver.query('_ldap._tcp.'+domain, 'SRV')
        logger.debug('Answer '+str(answer[0].split()[-1]))
    except Exception:
        answer = None
    if not answer:
        logger.debug('Resolving '+domain)
        try:
            # second, try standard lookup for the domain name
            answer = resolver.query(domain)
            logger.debug('Answer '+str(answer[0].split()[-1]))
        except Exception:
            pass
    if not answer:
        # last, try using the default name lookup for your host (may include hosts file)
        addr = get_host_by_name(domain)
        if addr:
            answer = [addr]
    return get_addr_by_host(str(answer[0]).split()[-1], name_server) if answer and len(answer) else None

def get_host_by_name(host):
    logger.debug('Resolving {} via default'.format(host))
    try:
        return socket.gethostbyname(host)
    except:
        pass
    return None

def get_addrs_by_host(host, name_server=None):
    ''' return list of addresses for the host '''
    resolver = get_resolver(name_server)
    try:
        answer = resolver.query(host)
        logger.debug('Resolved {} to {} via {}'.format(host, ', '.join([a.address for a in answer]),
                                                       name_server or 'default DNS'))
    except Exception:
        logger.debug('Name resolution failed for '+host)
        return []
    return [a.address for a in answer]

def get_addr_by_host(host, name_server=None):
    addrs = get_addrs_by_host(host, name_server)
    return addrs[0] if len(addrs) else None

def get_fqdn_by_addr(addr, name_server=None):
    resolver = get_resolver(name_server)
    arpa = '.'.join(reversed(addr.split('.'))) + '.in-addr.arpa.'
    try:
        answer = resolver.query(arpa, 'PTR', 'IN')
        logger.debug('Resolved {} to {} via {}'.format(arpa, str(answer[0])[:-1], name_server or 'default'))
    except Exception:
        logger.debug('Name resolution failed for '+arpa)
        return None
    return str(answer[0])[:-1]

def get_host_by_addr(addr, name_server=None):
    fqdn = get_fqdn_by_addr(addr, name_server)
    if fqdn:
        return fqdn.split('.', maxsplit=1)[0]
    return None

def dw(d):
    ''' convert attrs stored as dwords to an int '''
    return 0 if d == 0 else 0xffffffff + d + 1

def get_users(conn, dc, active_only=False):
    ''' get all domain users '''
    if active_only:
        raise NotImplementedError
    #search_filter = '(&(objectCategory=user)'
    else:
        search_filter = '(objectCategory=user)'
    results = []
    conn.search(dc, "(&(objectCategory=user)(cn>=m))", attributes=['userPrincipalName'])
    results.extend(conn.response)
    conn.search(dc, "(&(objectCategory=user)(!(cn>=m)))", attributes=['userPrincipalName'])
    results.extend(conn.response)
    #conn.search(dc, "(objectCategory=user)", attributes=['userPrincipalName'])
    return results

def get_groups(conn, dc):
    ''' get all domain users '''
    # use domain as base to get builtin and domain groups in one query
    # alternatively, you can do 2 queries with bases:
    #    cn=users,cn=mydomain,cn=com
    #    cn=users,cn=builtins,cn=mydomain,cn=com
    conn.search(dc, '(objectCategory=group)', attributes=['objectSid', 'groupType'])
    return [g for g in conn.response if g.get('dn', None)]

def get_computers(conn, dc, attributes=[], hostnames=[]):
    attributes = list(set(attributes + ['name', 'dNSHostName', 'whenCreated', 'operatingSystem',
                                        'operatingSystemServicePack', 'lastLogon', 'logonCount',
                                        'operatingSystemHotfix', 'operatingSystemVersion',
                                        'location', 'managedBy', 'description']))
    hostnames = set(map(str.lower, hostnames))
    results = []
    filters = []
    if len(hostnames):
        hosts = ''
        for h in hostnames:
            if h.count('.'):
                h = h.split('.', maxsplit=1)[0]
            hosts += '(cn={})'.format(h)
        if len(hostnames) > 1:
            hosts = '(|' + hosts + ')'
        filters.append('(&(objectCategory=computer)(cn>=m){})'.format(hosts))
        filters.append('(&(objectCategory=computer)(!(cn>=m)){})'.format(hosts))
    else:
        filters.append('(&(objectCategory=computer)(cn>=m))')
        filters.append('(&(objectCategory=computer)(!(cn>=m)))')
    for f in filters:
        conn.search(dc, f, attributes=attributes)
        results.extend(conn.response)
    return [g for g in results if g.get('dn', None)]

def gid_from_sid(sid):
    if type(sid) == str:
        sid = sid.encode()
    return struct.unpack('<H', sid[-4:-2])[0]

def get_user_dn(conn, dc, user):
    conn.search(dc, '(&(objectCategory=user)(|(userPrincipalName={}@*)(cn={})))'.format(user, user))
    return conn.response[0]['dn']

def get_user_groups(conn, dc, user):
    ''' get all groups for user, domain and local. see groupType attribute to check domain vs local.
    user should be a dn'''
    conn.search(dc, '(&(objectCategory=User)(distinguishedName='+user+'))', attributes=['memberOf', 'primaryGroupID'])
    group_dns = conn.response[0]['attributes']['memberOf']

    # get primary group which is not included in the memberOf attribute
    pgid = int(conn.response[0]['attributes']['primaryGroupID'][0])
    groups = get_groups(conn, dc)
    for g in groups:
        # Builtin group SIDs are returned as str's, not bytes
        if type(g['attributes']['objectSid'][0]) == str:
            g['attributes']['objectSid'][0] = g['attributes']['objectSid'][0].encode()
    gids = [gid_from_sid(g['attributes']['objectSid'][0]) for g in groups]
    group_dns.append(groups[gids.index(pgid)]['dn'])
    group_dns = list(map(str.lower, group_dns))
    return [g for g in groups if g['dn'].lower() in group_dns]

def get_users_in_group(conn, dc, group):
    ''' return all members of group '''
    groups = get_groups(conn, dc)
    group = [g for g in groups if cn(g.get('dn', '')).lower() == group.lower()][0] # get group dn
    gid = gid_from_sid(group['attributes']['objectSid'][0])
    # get all users with primaryGroupID of gid
    conn.search(dc, '(&(objectCategory=user)(primaryGroupID={}))'.format(gid),
                attributes=['distinguishedName', 'userPrincipalName'])
    users = [u for u in conn.response if u.get('dn', False)]
    # get all users in group using "memberOf" attribute. primary group is not included in the "memberOf" attribute
    conn.search(dc, '(&(objectCategory=user)(memberOf='+group['dn']+'))', attributes=['distinguishedName', 'userPrincipalName'])
    users += [u for u in conn.response if u.get('dn', False)]
    return users

def get_pwd_policy(conn, dc):
    ''' return non-default password policies for the domain '''
    base = 'cn=Password Settings Container,cn=System,'+dc
    # https://technet.microsoft.com/en-us/library/2007.12.securitywatch.aspx
    attrs = [
        'name',
        'msDS-PasswordReversibleEncryptionEnabled', # default is false which is good
        'msDS-PasswordHistoryLength',               # how many old pwds to remember
        'msds-PasswordComplexityEnabled',           # require different character groups
        'msDS-MinimumPasswordLength',
        'msDS-MinimumPasswordAge', # used to prevent abuse of msDS-PasswordHistoryLength
        'msDS-MaximumPasswordAge', # how long until password expires
        'msDS-LockoutThreshold',   # login failures allowed within the window
        'msDS-LockoutObservationWindow', # time window where failed auths are counted
        'msDS-LockoutDuration', # how long to lock user account after too many failed auths
        'msDS-PSOAppliesTo',    # dn's of affected users
        'msDS-PasswordSettingsPrecedence', # used to assign precedence when a user is member of multiple policies
    ]
    # grab all objects directly under the search base
    conn.search(base, '(objectCategory=*)', attributes=attrs, search_scope=ldap3.LEVEL)
    response = []
    for r in conn.response:
        if not r['dn'].lower().startswith('cn=password settings container,'):
            response.append(r)
    return response

def get_user_info(conn, dc, user):
    user_dn = get_user_dn(conn, dc, user)
    conn.search(dc, '(&(objectCategory=user)(distinguishedName={}))'.format(user_dn), attributes=['allowedAttributes'])
    allowed = set([a.lower() for a in conn.response[0]['attributes']['allowedAttributes']])
    attributes = [
        #'msexchhomeservername',
        #'usncreated',
        'whenCreated',
        'whenChanged',
        'memberOf',
        'groupMembershipSAM',
        'accountExpires',
        'msDS-UserPasswordExpiryTimeComputed',
        'displayName',
        'primaryGroupID',
        #'homeDirectory',
        'lastLogonTimestamp',
        'lastLogon',
        'lastLogoff',
        'logonWorkstation',
        'otherLoginWorkstations',
        'scriptPath',
        'userWorkstations',
        'displayName',
        'mail',
        'title',
        'samaccountname',
        'lockouttime',
        'lockoutduration',
        'description',
        'pwdlastset',
        'logoncount',
        'logonHours',
        'name',
        #'usnchanged',
        #'allowedAttributes',
        #'admincount',
        'badpasswordtime',
        'badPwdCount',
        'info',
        'distinguishedname',
        'userPrincipalName',
        'givenname',
        'middleName',
        'lastlogontimestamp',
        'useraccountcontrol',
        'objectGUID',
        'objectSid',
    ]
    attrs = [a for a in attributes if a.lower() in allowed]
    conn.search(dc, '(&(objectCategory=user)(distinguishedName={}))'.format(user_dn), attributes=attrs)
    return conn.response

class MyMD4Class():
    ''' class to add pass-the-hash support to pysmb '''
    @staticmethod
    def new():
        return MyMD4Class()
    def update(self, p):
        self.nthash = binascii.unhexlify(p.decode('utf-16-le'))
    def digest(self):
        return self.nthash

def get_default_pwd_policy(args, conn, dc):
    ''' default password policy is what gets returned by "net accounts"
    The policy is stored as a GPO on the sysvol share. It's stored in an INI file.
    The default policy is not returned by get_pwd_policy() '''
    if conn:
        conn.search('cn=Policies,cn=System,'+dc, '(cn={31B2F340-016D-11D2-945F-00C04FB984F9})',
                    attributes=['gPCFileSysPath'])
        gpo_path = conn.response[0]['attributes']['gPCFileSysPath'][0]
    else:
        gpo_path = r'\\' + args.domain + r'\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE'
    logger.debug('GPOPath '+gpo_path)
    sysvol, rel_path = gpo_path[2:].split('\\', 2)[-2:]
    rel_path += r'\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
    tmp_file = tempfile.NamedTemporaryFile(prefix='GptTmpl_', suffix='.inf')
    if not args.smbclient:
        try:
            from smb.SMBConnection import SMBConnection
            if args.nthash:
                import smb.ntlm
                smb.ntlm.MD4 = MyMD4Class.new
            dc_hostname = args.hostname or \
                          get_host_by_addr(args.server, args.name_server) or \
                          get_host_by_addr(args.server, args.server) or \
                          get_host_by_addr(args.server)
            if not dc_hostname:
                raise socket.herror
            logger.debug('dc_hostname: '+dc_hostname)
            use_pysmb = True
        except (ImportError, socket.herror) as e:
            if type(e) == ImportError:
                logger.info('Install pysmb to remove smbclient dependency')
            elif type(e) == socket.herror:
                logger.info('Failed to resolve server address')
            use_pysmb = False
    else:
        use_pysmb = False

    if use_pysmb:
        logger.debug('SMBConnection("{}", "{}", "adenum", "{}", domain="{}")'.format(
            args.username, args.password, dc_hostname, args.domain))
        conn = SMBConnection(args.username, args.password, 'adenum', dc_hostname, use_ntlm_v2=True,
                             domain=args.domain, is_direct_tcp=(args.smb_port != 139))
        logger.debug('connecting {}:{}'.format(args.server, args.smb_port))
        conn.connect(args.server, port=args.smb_port)
        attrs, size = conn.retrieveFile(sysvol, rel_path, tmp_file)
    else:
        cmd = ['smbclient', '-p', str(args.smb_port), '--user={}\\{}'.format(args.domain, args.username),
               '//{}/{}'.format(args.server, sysvol), '-c', 'get "{}" {}'.format(rel_path, tmp_file.name)]
        if args.nthash:
            cmd.insert(1, '--pw-nt-hash')
        logger.info('Running '+' '.join(cmd))
        result = subprocess.run(cmd, input=args.password.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.debug(result.stdout.decode())
        logger.debug(result.stderr.decode())
    tmp_file.seek(0)
    inf = tmp_file.read()
    if inf[:2] == b'\xff\xfe':
        inf = inf.decode('utf-16')
    else:
        inf = inf.decode()
    config = configparser.ConfigParser(delimiters=('=', ':', ','))
    config.read_string(inf)
    return config['System Access']

def timestr_or_never(t):
    return 'Never' if t in [0, 0x7FFFFFFFFFFFFFFF] else ft_to_str(t)

def user_handler(args, conn, dc):
    for u in [get_user_info(conn, dc, user)[0] for user in args.users]:
        if not u.get('attributes'):
            continue
        a = u['attributes']
        # print(a['objectGUID'])
        # print(a['objectSid'])
        # https://msdn.microsoft.com/en-us/library/ms680832.aspx
        print('UserName                 ', a['name'][0])
        print('FullName                 ', get_attr(a, 'givenName', ''), get_attr(a, 'middleName', ''))
        print('DistinguishedName        ', a['distinguishedName'][0])
        print('UserPrincipalName        ', get_attr(a, 'userPrincipalName', ''))
        print('Comment                  ', ','.join(a['description']))
        print('UserComment              ', ','.join(a['info']))
        print('DisplayName              ', ' '.join(a['displayName']))
        print('E-mail                   ', ' '.join(a['mail']))
        print('JobTitle                 ', ' '.join(a['title']))
        print('AccountCreated           ', gt_to_str(a['whenCreated'][0]))
        print('AccountActive            ', 'No' if int(a['userAccountControl'][0]) & 0x2 else 'Yes')

        try:
            print('AccountExpires           ', timestr_or_never(int(a['accountExpires'][0])))
            if len(a['lockoutTime']) == 0 or int(a['lockoutTime'][0]) == 0:
                print('LockoutTime              ', 'No')
            else:
                print('LockoutTime              ', timestr_or_never(int(a['lockoutTime'])))
            print('AccountLocked            ', 'Yes' if int(a['userAccountControl'][0]) & 0x10 else 'No')
            print('FailedLogins             ', a['badPwdCount'][0])
            print('LastFailedLogin          ', timestr_or_never(int(a['badPasswordTime'][0])))
            print('LogonCount               ', a['logonCount'][0])
            print('LastLogon                ', timestr_or_never(int(a['lastLogon'][0])))
        except:
            pass

        try:
            print('PasswordLastSet          ', timestr_or_never(int(a['pwdLastSet'][0])))
            print('PasswordExpires          ', 'No' if int(a['userAccountControl'][0]) & 0x10000 else 'Yes')
            #print('PasswordChangeable')
            print('UserMayChangePassword    ', 'No' if int(a['userAccountControl'][0]) & 0x40 else 'Yes')
            #print('Workstations allowed      ', ', '.join(a['userWorkstations']))
        except:
            pass

        groups = get_user_groups(conn, dc, u['dn'])
        primary_group = [g['dn'] for g in groups if struct.unpack('<H', g['attributes']['objectSid'][0][-4:-2])[0] == int(a['primaryGroupID'][0])][0]
        print('PrimaryGroup              "{}"'.format(primary_group if args.dn else cn(primary_group)))
        # group scopes: https://technet.microsoft.com/en-us/library/cc755692.aspx
        GROUP_SYSTEM = 0x1
        GROUP_GLOBAL = 0x2
        GROUP_DOMAIN_LOCAL = 0x4
        GROUP_UNIVERSAL = 0x8
        XGROUP_LOCAL = GROUP_SYSTEM | GROUP_DOMAIN_LOCAL
        XGROUP_GLOBAL = GROUP_GLOBAL | GROUP_UNIVERSAL
        for g in groups:
            logger.debug(hex(dw(int(g['attributes']['groupType'][0]))) + ' ' + cn(g['dn']))
        local_groups = [g['dn'] for g in groups if dw(int(g['attributes']['groupType'][0])) & XGROUP_LOCAL]
        global_groups = [g['dn'] for g in groups if dw(int(g['attributes']['groupType'][0])) & XGROUP_GLOBAL]
        print('LocalGroupMemberships    ', ', '.join(map(lambda x:'"{}"'.format(x if args.dn else cn(x)), local_groups)))
        print('GlobalGroupMemberships   ', ', '.join(map(lambda x:'"{}"'.format(x if args.dn else cn(x)), global_groups)))
        print('')

def users_handler(args, conn, dc):
    users = get_users(conn, dc)
    for u in users:
        if 'dn' in u:
            if args.dn:
                print(u['dn'])
            else:
                try:
                    print(u['attributes']['userPrincipalName'][0].split('@')[0])
                except:
                    # NOTE: CN is not guaranteed to be unique
                    print(cn(u['dn']))

def groups_handler(args, conn, dc):
    for g in get_groups(conn, dc):
        if args.dn:
            print(g['dn'])
        else:
            print(cn(g['dn']))

def group_handler(args, conn, dc):
    members = get_users_in_group(conn, dc, args.group)
    for u in members:
        if args.dn:
            print(u.get('dn', u))
        else:
            try:
                print(u['attributes']['userPrincipalName'][0].split('@')[0])
            except:
                print(cn(u['dn']))

def ping_host(addr, timeout=GTIMEOUT):
    ''' check if host is alive by first calling out to ping, then
    by initiating a connection on tcp/445 '''
    if not is_addr(addr):
        return False
    if sys.platform.lower().startswith('windows'):
        cmd = 'ping -n 1 -w {} {}'.format(timeout, addr)
    else:
        cmd = 'ping -c 1 -W {} {}'.format(timeout, addr)
    logger.debug('Running '+cmd)
    try:
        subprocess.check_call(cmd.split(), stderr=subprocess.STDOUT, stdout=open(os.devnull, 'w'))
        return True
    except Exception:
        pass
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    logger.debug('Connecting to {}:445'.format(addr))
    try:
        s.connect((addr, 445))
        return True
    except socket.timeout:
        return False

def computer_info_thread(computer, args):
    ''' runs as a thread to resolve and find uptime of the host '''
    hostname = computer['attributes']['dNSHostName'][0]
    info = ''
    if args.resolve or args.uptime or args.alive:
        for name_server in set([args.name_server, args.server, None]):
            addr = get_addr_by_host(hostname, name_server)
            if addr:
                break
        if addr:
            if args.alive and not ping_host(addr):
                logger.debug('Host '+addr+' is down')
                return
            info = 'Address: {}\n'.format(addr)
            if args.uptime:
                smbinfo = get_smb_info(addr)
                if smbinfo:
                    for k in sorted(smbinfo.keys()):
                        info += '{}: {}\n'.format(k, smbinfo[k])
                # uptime = get_uptime(addr)
                # if uptime:
                #     info += 'uptime: {}\n'.format(uptime)
        elif args.alive:
            logger.debug('Host '+addr+' may be down')
            return
    for a in sorted(computer['attributes'].keys()):
        if a.lower() in ['whencreated']:
            info += '{}: {}\n'.format(a, get_attr(computer, a, '', gt_to_str))
        elif a.lower() in ['lastlogon']:
            info += '{}: {}\n'.format(a, get_attr(computer, a, '', lambda x:ft_to_str(int(x))))
        else:
            info += '{}: {}\n'.format(a, ', '.join(computer['attributes'][a]))
    if args.dn:
        sys.stdout.write('dn: '+computer['dn'] + os.linesep + info + os.linesep)
    else:
        sys.stdout.write('cn: '+cn(computer['dn']) + os.linesep + info + os.linesep)

def computers_handler(args, conn, dc):
    computers = get_computers(conn, dc, args.attributes, args.computers)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as e:
        concurrent.futures.wait([e.submit(computer_info_thread, c, args) for c in computers])

def policy_handler(args, conn, dc):
    pol = get_default_pwd_policy(args, conn, dc)
    if pol:
        attrs = ['MinimumPasswordLength', 'PasswordComplexity', 'MinimumPasswordAge', 'MaximumPasswordAge',
                 'PasswordHistorySize', 'LockoutBadCount', 'ResetLockoutCount', 'LockoutDuration',
                 'RequireLogonToChangePassword', 'ForceLogoffWhenHourExpire', 'ClearTextPassword',
                 'LSAAnonymousNameLookup']
        print('-------- default domain policy --------')
        for a in attrs:
            if a in pol:
                print('{:30s} {}'.format(a, pol[a]))
        print('')
    # sort policies by precedence. precedence is used to determine which policy applies to a user
    # whem multiple policies are applied to him/her
    pols = sorted(get_pwd_policy(conn, dc), key=lambda p:int(p['attributes']['msDS-PasswordSettingsPrecedence'][0]))
    for a in [p['attributes'] for p in pols]:
        print('--------', a['name'][0], '--------')
        print('MinimumPasswordLength          ', a['msDS-MinimumPasswordLength'][0])
        print('ComplexityEnabled              ', a['msDS-PasswordComplexityEnabled'][0])
        print('MinimumPasswordAge             ', interval_to_minutes(int(a['msDS-MinimumPasswordAge'][0])) // 1440)
        print('MaximumPasswordAge             ', interval_to_minutes(int(a['msDS-MaximumPasswordAge'][0])) // 1440)
        print('HistorySize                    ', a['msDS-PasswordHistoryLength'][0])
        print('LockoutThreshold               ', a['msDS-LockoutThreshold'][0])
        print('LockoutObservationWindow       ', interval_to_minutes(int(a['msDS-LockoutObservationWindow'][0])))
        print('LockoutDuration                ', interval_to_minutes(int(a['msDS-LockoutDuration'][0])))
        print('ReversibleEncryptionEnabled    ', a['msDS-PasswordReversibleEncryptionEnabled'][0])
        print('Precedence                     ', a['msDS-PasswordSettingsPrecedence'][0])
        print('Applies to')
        for dn in a['msDS-PSOAppliesTo']:
            print('\t'+dn) if args.dn else print('\t'+cn(dn))
        print('')

def custom_query(conn, base, _filter, scope=ldap3.SUBTREE, attrs=None):
    conn.search(base, _filter, search_scope=scope, attributes=attrs)
    return conn.response

def query_handler(args, conn, dc):
    if args.scope.lower() == 'level':
        scope = ldap3.LEVEL
    elif args.scope.lower() == 'base':
        scope = ldap3.BASE
    elif args.scope.lower() in ['sub', 'subtree']:
        scope = ldap3.SUBTREE
    else:
        raise ValueError('scope must be either "level", "base", or "subtree"')

    if args.base:
        base = args.base+','+dc if args.append else args.base
    else:
        base = dc

    if args.allowed:
        # range doesn't seem to work...
        response = custom_query(conn, base, args.filter, scope=scope, attrs=['allowedAttributes', 'range=0-1'])
        print('AllowedAttributes')
        for a in conn.response[0]['attributes']['allowedAttributes']:
            print('\t', a)
        return

    response = custom_query(conn, base, args.filter, scope=scope, attrs=args.attributes)
    for r in response:
        if 'dn' in r:
            print(r['dn'])
            for a in args.attributes:
                print(a, get_attr(r, a, ''))
            print('')

def modify_handler(args, conn, dc):
    # 'MODIFY_ADD', 'MODIFY_DELETE', 'MODIFY_INCREMENT', 'MODIFY_REPLACE'
    raise NotImplementedError
    action_map = {'add':ldap3.MODIFY_ADD, 'del':ldap3.MODIFY_DELETE, 'inc':ldap3.MODIFY_INCREMENT, 'replace':ldap3.MODIFY_REPLACE}
    conn.modify(dn, {args.attribute:[(ldap3.MODIFY_REPLACE, args.values)]})
    logger.debug(conn.result)

def cn(dn):
    ''' return common name from distinguished name '''
    return dn.split(',')[0].split('=')[-1]

def dt_to_lt(dt):
    ''' convert datetime object to localtime '''
    return dt.replace(tzinfo=datetime.timezone.utc).astimezone(tz=None)

def ft_to_dt(win):
    ''' convert windows FILETIME to datetime '''
    micros = win / 10.0
    return dt_to_lt(datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=micros))

def ft_to_str(win):
    return ft_to_dt(win).strftime('%m/%d/%Y %I:%M:%S %p')

def interval_to_minutes(i):
    ''' convert interval values (100 ns intervals) to seconds '''
    return int((-i / 10000000) / 60)

def gt_to_dt(g):
    ''' convert generalized time to datetime '''
    return dt_to_lt(datetime.datetime.strptime(g.split('.')[0], '%Y%m%d%H%M%S'))

def gt_to_str(g):
    return gt_to_dt(g).strftime('%m/%d/%Y %I:%M:%S %p')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=DESCRIPTION, formatter_class=argparse.RawTextHelpFormatter)
    user_parser = parser.add_mutually_exclusive_group()
    user_parser.add_argument('-u', '--username', default='', help='AD user. default is null user.')
    user_parser.add_argument('--anonymous', action='store_true', help='anonymous access')
    parser.add_argument('-p', '--password', default=hashlib.new('md4', b'').hexdigest(), help='password')
    parser.add_argument('--nthash', action='store_true', help='password is an NTLM hash')
    parser.add_argument('-P', dest='prompt', action='store_true', help='prompt for password')
    parser.add_argument('-s', '--server', help='domain controller addr or name. default: dns lookup on domain')
    parser.add_argument('-H', '--hostname', help='DC hostname. never required')
    parser.add_argument('-d', '--domain', help='default is to use domain of server')
    parser.add_argument('--timeout', type=int, default=GTIMEOUT, help='timeout for network operations')
    parser.add_argument('--threads', type=int, default=50, help='name resolution/uptime worker count')
    parser.add_argument('--port', type=int, help='default 389 or 636 with --tls. 3268 for global catalog')
    parser.add_argument('--smb-port', dest='smb_port', default=445, type=int, help='default 445')
    parser.add_argument('--smbclient', action='store_true', help='force use of smbclient over pysmb')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('-v', '--version', type=int, choices=[1,2,3], default=3, help='specify ldap version')
    parser.add_argument('--debug', action='store_true', help='implies --verbose')
    parser.add_argument('--name-server', dest='name_server', help='specify name server. typically this is the domain controller')
    parser.add_argument('--dn', action='store_true', help='list distinguished names of AD objects')
    parser.add_argument('--info', action='store_true', help='get server info')
    parser.add_argument('--schema', action='store_true', help='get server schema')
    parser.add_argument('--insecure', action='store_true', help='ignore invalid tls certs')
    #parser.add_argument('--cert', help='')
    #parser.add_argument('--auth', default='ntlm', type=str.lower, choices=['ntlm', 'kerb'], help='auth type')
    parser.set_defaults(handler=None)

    tls_group = parser.add_mutually_exclusive_group()
    tls_group.add_argument('--tls', action='store_true', help='initiate connection with TLS')
    tls_group.add_argument('--start-tls', dest='starttls', action='store_true',  help='use START_TLS')

    subparsers = parser.add_subparsers(help='choose an action')
    users_parser = subparsers.add_parser('users', help='list all users')
    users_parser.set_defaults(handler=users_handler)
    user_parser = subparsers.add_parser('user', help='get user info')
    user_parser.set_defaults(handler=user_handler)
    user_parser.add_argument('users', nargs='+', help='users to search')

    groups_parser = subparsers.add_parser('groups', help='list all groups')
    groups_parser.set_defaults(handler=groups_handler)
    group_parser = subparsers.add_parser('group', help='get group info')
    group_parser.set_defaults(handler=group_handler)
    group_parser.add_argument('group', help='group to search')
    group_parser.add_argument('-m', '--members', help='retrieve group members')

    policy_parser = subparsers.add_parser('policy', help='get policy info')
    policy_parser.set_defaults(handler=policy_handler)

    computer_parser = subparsers.add_parser('computer', help='list computer')
    computer_parser.set_defaults(handler=computers_handler)
    computer_parser.add_argument('-u', '--uptime', action='store_true', help='get uptime via SMB2')
    computer_parser.add_argument('-r', '--resolve', action='store_true', help='resolve hostnames')
    computer_parser.add_argument('-a', '--attributes', default=[], type=lambda x:x.split(','), help='additional attributes to retrieve')
    computer_parser.add_argument('computers', nargs='+', help='computers to search')
    computer_parser.add_argument('--alive', action='store_true', help='only show alive hosts')

    computers_parser = subparsers.add_parser('computers', help='list computers')
    computers_parser.set_defaults(handler=computers_handler)
    computers_parser.set_defaults(computers=[])
    computers_parser.add_argument('-u', '--uptime', action='store_true', help='get uptime via SMB2')
    computers_parser.add_argument('-r', '--resolve', action='store_true', help='resolve hostnames')
    computers_parser.add_argument('-a', '--attributes', default=[], type=lambda x:x.split(','),
                                  help='additional attributes to retrieve')
    computers_parser.add_argument('--alive', action='store_true', help='only show alive hosts')

    query_parser = subparsers.add_parser('query', help='perform custom ldap query')
    query_parser.set_defaults(handler=query_handler)
    query_parser.add_argument('-b', '--base', help='search base. default is DC')
    query_parser.add_argument('-a', '--append', action='store_true', default=False, help='append base to DC')
    query_parser.add_argument('-f', '--filter', required=True, help='search filter')
    query_parser.add_argument('-s', '--scope', type=str.lower,  default='base', choices=['base', 'level', 'subtree'],
                              help='search scope')
    attr_group = query_parser.add_mutually_exclusive_group()
    attr_group.add_argument('--allowed', action='store_true', help='display allowed attributes')
    attr_group.add_argument('attributes', default=[], nargs='*', help='attributes to retrieve')
    modify_parser = subparsers.add_parser('modify', help='modify an object attribute')
    modify_parser.set_defaults(handler=modify_handler)
    modify_parser.add_argument('action', choices=['add', 'del', 'inc', 'replace'], help='action to perform')
    modify_parser.add_argument('distinguished_name', metavar='dn', help='distinguishedName')
    modify_parser.add_argument('attribute', help='attribute to modify')
    modify_parser.add_argument('values', nargs='*', default=[], help='value(s) to add/modify')

    args = parser.parse_args()
    GTIMEOUT = args.timeout

    if args.debug:
        logger.setLevel(logging.DEBUG)
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter('[%(levelname)s]:%(lineno)s %(message)s'))
        logger.addHandler(h)
    elif args.verbose:
        logger.setLevel(logging.INFO)
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
        logger.addHandler(h)

    if args.server and not is_addr(args.server):
        # resolve DC hostname
        args.server = get_addr_by_host(args.server, args.name_server) or get_host_by_name(args.server)
        if not args.server:
            print('Error: Failed to resolve DC hostname')
            sys.exit()

    if args.username.find('\\') != -1:
        if args.domain:
            args.username = args.username.split('\\')[-1]
        else:
            args.domain, args.username = args.username.split('\\')

    if not args.domain or args.domain.count('.') == 0:
        logger.debug('checking for domain name')
        args.domain = None
        if not args.server:
            if args.name_server:
                args.domain = get_fqdn_by_addr(args.name_server, args.name_server)
        else:
            args.domain = get_fqdn_by_addr(args.server, args.name_server)
            if not args.domain and args.server != args.name_server:
                # try query against the domain controller
                args.domain = get_fqdn_by_addr(args.server, args.server)
        if not args.domain:
            print('Error: Failed to get domain. Try supplying the fqdn with --domain')
            sys.exit()
        args.domain = args.domain.split('.', maxsplit=1)[-1]
        logger.info('Found domain: '+args.domain)

    # determine port if not specified
    if not args.port:
        if args.tls:
            args.port = 636
        else:
            args.port = 389

    if not args.server:
        # attempt to find a DC
        logger.info('Looking for domain controller for '+args.domain)
        args.server = get_dc(args.domain, args.name_server)
        if not args.server:
            print('Error: Failed to find a domain controller')
            sys.exit()
        logger.info('Found a domain controller for {} at {}'.format(args.domain, args.server))

    dc = 'dc='+args.domain.replace('.', ',dc=')
    logger.debug('DC     '+args.server)
    logger.debug('PORT   '+str(args.port))
    logger.debug('DOMAIN '+args.domain)
    logger.debug('LOGIN  '+args.username)
    logger.debug('DNS    '+ (args.name_server or 'default'))
    if not is_private_addr(args.server) and not args.insecure:
        raise Warning('Aborting due to public LDAP server. use --insecure to override')

    if args.info and args.schema:
        get_info = ldap3.ALL
    elif args.info:
        get_info = ldap3.DSA
    elif args.schema:
        get_info = ldap3.SCHEMA
    else:
        get_info = None
    
    # avail: PROTOCOL_SSLv23, PROTOCOL_TLSv1, PROTOCOL_TLSv1_1, PROTOCOL_TLSv1_2
    username = None
    password = None
    if not args.anonymous:
        username =  args.domain+'\\'+args.username
        if args.prompt:
            args.password = getpass.getpass()
        if args.nthash:
            if len(args.password) != 32:
                print('Error: ntlm hash must be 32 hex chars')
                sys.exit()
            # ldap3 takes LM:NTLM hash then discards the LM hash so we fake the LM hash
            password = '00000000000000000000000000000000:'+args.password
        else:
            password = args.password
            logger.debug('NTHASH '+hashlib.new('md4', password.encode('utf-16-le')).hexdigest())

    tls_config = ldap3.Tls(validate=ssl.CERT_NONE if args.insecure else ssl.CERT_OPTIONAL,
                           version=ssl.PROTOCOL_TLSv1)
    server = ldap3.Server(args.server, get_info=get_info, use_ssl=args.tls, port=args.port, tls=tls_config)
    auth = ldap3.ANONYMOUS if args.anonymous else ldap3.NTLM
    conn = CachingConnection(server, user=username, password=password, authentication=auth,
                             version=args.version, read_only=False, auto_range=True,
                             auto_bind=False, receive_timeout=args.timeout)

    conn.open()
    if args.starttls:
        conn.start_tls()
    conn.bind()

    if args.info:
        print(server.info)
    if args.schema:
        print(server.schema)

    if not conn.bound:
        print('Error: failed to bind')
        sys.exit()
    logger.debug(conn.extend.standard.who_am_i())

    if args.handler:
        args.handler(args, conn, dc)
    conn.unbind()
