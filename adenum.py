import sys
import os
import struct
import argparse
import socket
import configparser
import logging
import hashlib
import ssl
import subprocess
import getpass
import hashlib
import datetime
import tempfile
# non-std
import ldap3
# NOTE: dnspython and pysmb are imported on demand

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
from the sysvol file share.

= EXAMPLES =

NOTE: when specifying a domain with -d, ensure that your system
is configured to use the DNS server for the domain. Alternatively,
you can specify your domain controller with -s if it is a name server.

List password policies
    python3 adenum.py -u USER -P -d mydomain.local policy

List all users and groups
    python3 adenum.py -u USER -P -d mydomain.local users
    python3 adenum.py -u USER -P -d mydomain.local groups

List domain admins
    python3 adenum.py -u USER -P -d mydomain.local group "domain admins"

= RESOURCES =

all defined AD attributes
https://msdn.microsoft.com/en-us/library/ms675090(v=vs.85).aspx

user account
https://msdn.microsoft.com/en-us/library/ms680832.aspx
'''

class CachingConnection(ldap3.Connection):
    ''' Subclass of ldap3.Connection which uses the range attribute
    to gather all results. It will also cache searches. '''
    def __init__(self, *args, **kwargs):
        self.cache = {}
        kwargs['auto_range'] = True
        ldap3.Connection.__init__(self, *args, **kwargs)
    def search(self, search_base, search_filter, search_scopt=ldap3.SUBTREE, **kwargs):
        if 'attributes' not in kwargs:
            kwargs['attributes'] = []
        kwargs['attributes'].append('range=0-*')
        sha1 = hashlib.new('sha1', b''.join(
            str(a).lower().encode() for a in [search_base, search_filter]+list(kwargs.values()))).digest()
        if sha1 in self.cache:
            logging.debug('CACHE HIT')
            self.response = self.cache[sha1]
        logging.debug('SEARCH ({}) {} ATTRS {}'.format(search_base, search_filter, ', '.join(kwargs['attributes'])))
        super().search(
            search_base,
            search_filter,
            **kwargs
        )
        logging.debug('RESULT '+str(self.result))
        self.cache[sha1] = self.response

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

def get_resolver(name_server=None):
    import dns.resolver
    if name_server:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [name_server]
    else:
        # use nameserver configured for the host
        resolver = dns.resolver
    return resolver

def get_dc(domain, name_server=None):
    ''' return the domain controller for a given domain '''
    resolver = get_resolver(name_server)
    logging.debug('Resolving _ldap._tcp.'+domain)
    try:
        answer = resolver.query('_ldap._tcp.'+domain, 'SRV')
    except Exception:
        return None
    return get_addr_by_host(str(answer[0]).split()[-1], name_server)

def get_addrs_by_host(host, name_server=None):
    ''' return list of addresses for the host '''
    resolver = get_resolver(name_server)
    try:
        answer = resolver.query(host)
    except Exception:
        return None
    return [a.address for a in answer]

def get_addr_by_host(host, name_server=None):
    return get_addrs_by_host(host, name_server)[0]

def get_fqdn_by_addr(addr, name_server=None):
    resolver = get_resolver(name_server)
    arpa = '.'.join(reversed(addr.split('.'))) + '.in-addr.arpa.'
    try:
        answer = resolver.query(arpa, 'PTR', 'IN')
    except Exception:
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

def get_users(conn, dc):
    ''' get all domain users '''
    base = dc
    conn.search(base, '(objectCategory=user)', attributes=['userPrincipalName'])
    return conn.response

def get_groups(conn, dc):
    ''' get all domain users '''
    # use domain as base to get builtin and domain groups in one query
    # alternatively, you can do 2 queries with bases:
    #    cn=users,cn=mydomain,cn=com
    #    cn=users,cn=builtins,cn=mydomain,cn=com
    base = dc
    conn.search(base, '(objectCategory=group)', attributes=['objectSid', 'groupType'])
    return [g for g in conn.response if g.get('dn', None)]

def get_computers(conn, dc):
    attributes = ['name', 'dNSHostName', 'whenCreated', 'operatingSystem', 'operatingSystemServicePack',
                  'lastLogon', 'logonCount']
    conn.search(dc, '(objectCategory=computer)', attributes=attributes)
    return [g for g in conn.response if g.get('dn', None)]

def gid_from_sid(sid):
    if type(sid) == str:
        sid = sid.encode()
    return struct.unpack('<H', sid[-4:-2])[0]

def get_user_dn(conn, dc, user):
    base = dc
    conn.search(base, '(&(objectCategory=user)(|(userPrincipalName={}@*)(cn={})))'.format(user, user))
    return conn.response[0]['dn']

def get_user_groups(conn, dc, user):
    ''' get all groups for user, domain and local. see groupType attribute to check domain vs local '''
    base = dc
    user = get_user_dn(conn, dc, user)
    conn.search(base, '(&(objectCategory=User)(distinguishedName='+user+'))', attributes=['memberOf', 'primaryGroupID'])
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
        'msds-PasswordComplexityEnabled',           # require character groups
        'msDS-MinimumPasswordLength',
        'msDS-MinimumPasswordAge', # used to prevent abuse of msDS-PasswordHistoryLength
        'msDS-MaximumPasswordAge', # how long until password expires
        'msDS-LockoutThreshold',
        'msDS-LockoutObservationWindow',
        'msDS-LockoutDuration',
        'msDS-PSOAppliesTo',    # dn's of affected users
        'msDS-PasswordSettingsPrecedence', # used to assign precedence when a user is member of multiple policies
    ]
    # grab all objects directly under the search base
    conn.search(base, '(objectCategory=*)', attributes=attrs, search_scope=ldap3.LEVEL)
    return conn.response

def get_user_info(conn, dc, user):
    base = dc
    user_dn = get_user_dn(conn, dc, args.user)
    conn.search(base, '(&(objectCategory=user)(distinguishedName={}))'.format(user_dn), attributes=['allowedAttributes'])
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
    ]
    attrs = [a for a in attributes if a.lower() in allowed]
    conn.search(base, '(&(objectCategory=user)(distinguishedName={}))'.format(user_dn), attributes=attrs)
    return conn.response


def MyMD4():
    return MyMD4Class()
class MyMD4Class():
    def update(self, p):
        self.nthash = p.decode('utf-16-le').encode()
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
    logging.debug('GPOPath '+gpo_path)
    sysvol, rel_path = gpo_path[2:].split('\\', 2)[-2:]
    rel_path += r'\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
    tmp_file = tempfile.NamedTemporaryFile(prefix='GptTmpl_', suffix='.inf')
    if not args.smbclient:
        try:
            from smb.SMBConnection import SMBConnection
            if args.nthash:
                import smb.ntlm
                smb.ntlm.MD4 = MyMD4
            dc_hostname = args.hostname or get_host_by_addr(args.server, args.server) or get_host_by_addr(args.server)
            if not dc_hostname:
                raise socket.herror
            logging.debug('dc_hostname: '+dc_hostname)
            use_pysmb = True
        except (ImportError, socket.herror) as e:
            if type(e) == ImportError:
                logging.info('Install pysmb to remove smbclient dependency')
            elif type(e) == socket.herror:
                logging.info('Failed to resolve server address')
            use_pysmb = False
    else:
        use_pysmb = False
    if use_pysmb:
        logging.debug('SMBConnection("{}", "{}", "adenum", "{}", domain="{}")'.format(
            args.username, args.password, dc_hostname, args.domain))
        conn = SMBConnection(args.username, args.password, 'adenum', dc_hostname, use_ntlm_v2=True,
                             domain=args.domain, is_direct_tcp=(args.smb_port != 139))
        logging.debug('connecting {}:{}'.format(args.server, args.smb_port))
        conn.connect(args.server, port=args.smb_port)
        attrs, size = conn.retrieveFile(sysvol, rel_path, tmp_file)
    else:
        cmd = ['smbclient', '-p', str(args.smb_port), '--user={}\\{}'.format(args.domain, args.username),
               '//{}/{}'.format(args.server, sysvol), '-c', 'get "{}" {}'.format(rel_path, tmp_file.name)]
        if args.nthash:
            cmd.insert(1, '--pw-nt-hash')
        logging.info('Running '+' '.join(cmd))
        result = subprocess.run(cmd, input=args.password.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logging.debug(result.stdout.decode())
        logging.debug(result.stderr.decode())
    tmp_file.seek(0)
    inf = tmp_file.read()
    if inf[:2] == b'\xff\xfe':
        inf = inf.decode('utf-16')
    else:
        inf = inf.decode()
    config = configparser.ConfigParser()
    config.read_string(inf)
    return config['System Access']

def timestr_or_never(t):
    return 'Never' if t in [0, 0x7FFFFFFFFFFFFFFF] else ft_to_str(t)

def user_handler(args, conn, dc):
    for u in get_user_info(conn, dc, args.user):
        if not u.get('attributes'):
            continue
        a = u['attributes']
        # https://msdn.microsoft.com/en-us/library/ms680832.aspx
        print('User name                 ', a['name'][0])
        print('Full Name                 ', get_attr(a, 'givenName', ''), get_attr(a, 'middleName', ''))
        print('Distinguished Name        ', a['distinguishedName'][0])
        print('UserPrincipalName         ', get_attr(a, 'userPrincipalName', ''))
        print('Comment                   ', ','.join(a['description']))
        print("User's comment            ", ','.join(a['info']))
        print('Display name              ', ' '.join(a['displayName']))
        print('E-mail                    ', ' '.join(a['mail']))
        print('Job title                 ', ' '.join(a['title']))
        print('Account created           ', gt_to_str(a['whenCreated'][0]))
        print('Account active            ', 'No' if int(a['userAccountControl'][0]) & 0x2 else 'Yes')

        try:
            print('Account expires           ', timestr_or_never(int(a['accountExpires'][0])))
            if len(a['lockoutTime']) == 0 or int(a['lockoutTime'][0]) == 0:
                print('Lockout time              ', 'No')
            else:
                print('Lockout time              ', timestr_or_never(int(a['lockoutTime'])))
            print('Account locked            ', 'Yes' if int(a['userAccountControl'][0]) & 0x10 else 'No')
            print('Failed logins             ', a['badPwdCount'][0])
            print('Last failed login         ', timestr_or_never(int(a['badPasswordTime'][0])))
            print('Logon count               ', a['logonCount'][0])
            print('Last logon                ', timestr_or_never(int(a['lastLogon'][0])))
        except:
            pass
        print('')

        try:
            print('Password last set         ', timestr_or_never(int(a['pwdLastSet'][0])))
            #0x00010000 never
            print('Password expires          ', 'No' if int(a['userAccountControl'][0]) & 0x10000 else 'Yes')
            print('Password changeable')
            print('User may change password  ', 'No' if int(a['userAccountControl'][0]) & 0x40 else 'Yes')
            print('')
            print('Workstations allowed      ', ', '.join(a['userWorkstations']))
            print('Logon script              ', ', '.join(a['scriptPath']))
            #print('Logon hours allowed       ', a['logonHours'])
        except:
            pass
        groups = get_user_groups(conn, dc, args.user)
        primary_group = [g['dn'] for g in groups if struct.unpack('<H', g['attributes']['objectSid'][0][-4:-2])[0] == int(a['primaryGroupID'][0])][0]
        print('PrimaryGroup               "{}"'.format(primary_group if args.dn else cn(primary_group)))
        local_groups = [g['dn'] for g in groups if dw(int(g['attributes']['groupType'][0])) & 0x4]
        global_groups = [g['dn'] for g in groups if dw(int(g['attributes']['groupType'][0])) & 0x8]
        print('Local Group Memberships   ', ', '.join(map(lambda x:'"{}"'.format(x if args.dn else cn(x)), local_groups)))
        print('Global Group memberships  ', ', '.join(map(lambda x:'"{}"'.format(x if args.dn else cn(x)), global_groups)))

def users_handler(args, conn, dc):
    users = get_users(conn, dc)
    for u in users:
        if 'dn' in u:
            if args.dn:
                print(u['dn'])
            else:
                #print(u['attributes']['userPrincipalName'][0].split('@')[0])
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

def computers_handler(args, conn, dc):
    '''     attributes = ['name', 'dNSHostName', 'whenCreated', 'operatingSystem', 'operatingSystemServicePack',
                  'lastLogon', 'logonCount']
    '''
    computers = get_computers(conn, dc)
    for c in computers:
        info = '"{} {}" "created {}"'.format(
            get_attr(c, 'operatingSystem', ''),
            get_attr(c, 'operatingSystemServicePack', ''),
            get_attr(c, 'whenCreated', '', gt_to_str),
#            get_attr(c, 'lastLogon', '', lambda x: interval_to_minutes(-int(x)) // 1440),
        )
        if args.dn:
            print(c.get('dn', c), info)
        else:
            print(cn(c['dn']), info)

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
    pols = get_pwd_policy(conn, dc)
    # sort policies by precedence
    pols = sorted(pols, key=lambda p:int(p['attributes']['msDS-PasswordSettingsPrecedence'][0]))
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
    elif args.scope.lower() == 'subtree':
        scope = ldap3.SUBTREE
    else:
        raise ValueError('scope must be either "level", "base", or "subtree"')

    if args.base:
        base = args.base+','+dc if args.append else args.base
    else:
        base = dc

    if args.allowed:
        response = custom_query(conn, base, args.filter, scope=scope, attrs=['allowedAttributes'])
        for a in conn.response[0]['attributes']['allowedAttributes']:
            print(a)
        return

    response = custom_query(conn, base, args.filter, scope=scope, attrs=args.attributes)
    for r in response:
        if 'dn' in r:
            print(r['dn'])
            for a in args.attributes:
                print(get_attr(r, a, ''))
            print('')

def modify_handler(args, conn, dc):
    # 'MODIFY_ADD', 'MODIFY_DELETE', 'MODIFY_INCREMENT', 'MODIFY_REPLACE'
    #args.distinguished_name
    raise NotImplementedError
    action_map = {'add':ldap3.MODIFY_ADD, 'del':ldap3.MODIFY_DELETE, 'inc':ldap3.MODIFY_INCREMENT, 'replace':ldap3.MODIFY_REPLACE}
    conn.modify(dn, {args.attribute:[(ldap3.MODIFY_REPLACE, args.values)]})
    logging.debug(conn.result)

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
    parser.add_argument('--nthash', action='store_true', default=False, help='password is an NTLM hash')
    parser.add_argument('-P', dest='prompt', default=False, action='store_true', help='prompt for password')
    parser.add_argument('-s', '--server', help='domain controller addr or name. default: dns lookup on domain')
    parser.add_argument('-H', '--hostname', default=None, help='DC hostname. never required')
    parser.add_argument('-d', '--domain', default=None, help='default is to use domain of server')
    parser.add_argument('--port', default=None, type=int, help='default 389 or 636 with --tls')
    parser.add_argument('--smb-port', dest='smb_port', default=445, type=int, help='default 445')
    parser.add_argument('--smbclient', action='store_true', default=False, help='force use of smbclient over pysmb')
    parser.add_argument('--verbose', action='store_true', default=False)
    parser.add_argument('-v', '--version', type=int, choices=[1,2,3], default=3, help='specify ldap version')
    parser.add_argument('--debug', action='store_true', default=False, help='implies --verbose')
    parser.add_argument('--dn', action='store_true', default=False, help='list distinguished names of AD objects')
    parser.add_argument('--info', action='store_true', default=False, help='get server info')
    parser.add_argument('--schema', action='store_true', default=False, help='get server schema')
    parser.add_argument('--insecure', action='store_true', default=False, help='ignore invalid tls certs')
    parser.add_argument('--system', action='store_true', default=False, help='use system DHCP settings to find DC (/etc/resolv.conf)')
    #parser.add_argument('--cert', help='')
    #parser.add_argument('--auth', default='ntlm', type=str.lower, choices=['ntlm', 'kerb'], help='auth type')
    parser.set_defaults(handler=None)

    tls_group = parser.add_mutually_exclusive_group()
    tls_group.add_argument('--tls', action='store_true', default=False, help='initiate connection with TLS')
    tls_group.add_argument('--start-tls', dest='starttls', action='store_true', default=False, help='use START_TLS')

    subparsers = parser.add_subparsers(help='choose an action')
    users_parser = subparsers.add_parser('users', help='list all users')
    users_parser.set_defaults(handler=users_handler)
    user_parser = subparsers.add_parser('user', help='get user info')
    user_parser.set_defaults(handler=user_handler)
    user_parser.add_argument('user', help='user to search')

    groups_parser = subparsers.add_parser('groups', help='list all groups')
    groups_parser.set_defaults(handler=groups_handler)
    group_parser = subparsers.add_parser('group', help='get group info')
    group_parser.set_defaults(handler=group_handler)
    group_parser.add_argument('group', help='group to search')
    group_parser.add_argument('-m', '--members', help='retrieve group members')

    policy_parser = subparsers.add_parser('policy', help='get policy info')
    policy_parser.set_defaults(handler=policy_handler)

    computers_parser = subparsers.add_parser('computers', help='list computers')
    computers_parser.set_defaults(handler=computers_handler)

    query_parser = subparsers.add_parser('query', help='perform custom ldap query')
    query_parser.set_defaults(handler=query_handler)
    query_parser.add_argument('-b', '--base', help='search base. default is DC')
    query_parser.add_argument('-a', '--append', action='store_true', default=False, help='append base to DC')
    query_parser.add_argument('-f', '--filter', required=True, help='search filter')
    query_parser.add_argument('-s', '--scope', type=str.lower,  default='base', choices=['base', 'level', 'subtree'],
                              help='search scope')
    attr_group = query_parser.add_mutually_exclusive_group()
    attr_group.add_argument('--allowed', default=False, action='store_true', help='display allowed attributes')
    attr_group.add_argument('attributes', default=[], nargs='*', help='attributes to retrieve')
    modify_parser = subparsers.add_parser('modify', help='modify an object attribute')
    modify_parser.set_defaults(handler=modify_handler)
    modify_parser.add_argument('action', choices=['add', 'del', 'inc', 'replace'], help='action to perform')
    modify_parser.add_argument('distinguished_name', metavar='dn', help='distinguishedName')
    modify_parser.add_argument('attribute', help='attribute to modify')
    modify_parser.add_argument('values', nargs='*', default=[], help='value(s) to add/modify')

    args = parser.parse_args()

    #logging.getLogger('ldap3').setLevel(logging.WARNING)
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s]:%(lineno)s %(message)s')
    elif args.verbose:
        logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

    # check resolv.conf for possible domains and nameservers (typically DCs)
    if args.system:
        if os.path.exists('/etc/resolv.conf'):
            with open('/etc/resolv.conf') as fp:
                lines = [l for l in fp.readlines() if l[0] != '#']
            nameservers = []
            domains = []
            for l in lines:
                cols = l.split()
                if cols[0] == 'search':
                    domains += cols[1:]
                elif cols[0] == 'nameserver':
                    if cols[1].split('.')[0] != '127':
                        nameservers.append(cols[1])
            if len(nameservers) and not args.server:
                args.server = nameservers[0]
                logging.debug('domain '+nameservers[0])
            if len(domains) and not args.domain:
                args.domain = domains[0]
                logging.debug('search '+domains[0])
        else:
            print('Failed to find DC/domain using system settings')
            sys.exit()

    if not is_addr(args.server):
        logging.debug('Resolving '+args.server)
        args.server = socket.gethostbyname(args.server)
        logging.debug('Answer '+args.server)

    if not args.domain or args.domain.count('.') == 0:
        if not args.server:
            print('must supply at least 1 of --domain, --server, --system')
            sys.exit()
        args.domain = get_fqdn_by_addr(args.server, args.server).split('.', maxsplit=1)[-1]
        logging.info('Found domain: '+args.domain)

    # determine port if non specified
    if not args.port:
        if args.tls:
            args.port = 636
        else:
            args.port = 389

    if not args.server:
        addrs = get_addrs_by_host(args.domain)
        logging.info('Resolved '+args.domain)
        for a in addrs:
            logging.info('\t'+a)
        args.server = addrs[0]

    dc = 'dc='+args.domain.replace('.', ',dc=')
    logging.debug('DC     '+args.server)
    logging.debug('PORT   '+str(args.port))
    logging.debug('DOMAIN '+args.domain)
    logging.debug('LOGIN  '+args.username)
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
            logging.debug('NTHASH '+hashlib.new('md4', password.encode('utf-16-le')).hexdigest())

    tls_config = ldap3.Tls(validate=ssl.CERT_NONE if args.insecure else ssl.CERT_OPTIONAL,
                           version=ssl.PROTOCOL_TLSv1)
    server = ldap3.Server(args.server, get_info=get_info, use_ssl=args.tls, port=args.port, tls=tls_config)
    auth = ldap3.ANONYMOUS if args.anonymous else ldap3.NTLM
    conn = CachingConnection(server, user=username, password=password, authentication=auth,
                             version=args.version, read_only=False, auto_range=True, auto_bind=False)

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
    logging.debug(conn.extend.standard.who_am_i())

    if args.handler:
        args.handler(args, conn, dc)
    conn.unbind()
