import math
import ldap3
import socket
import logging
import binascii
import tempfile
import subprocess
import configparser

from modules.adldap import *
from modules.convert import *
from modules.names import *

logger = logging.getLogger(__name__)


def get_all(conn, search_base, simple_filter, attributes=[]):
    ''' this whole routine could be better '''
    if '(cn' in simple_filter.lower():
        raise ValueError('search filter must not contain CN')

    cs = '0123456789abcdefghijklmnopqrstuvwxyz'
    def half(l, r):
        if r[-1] == cs[0]:
            r += cs[-1]
        else:
            r = r[:-1] + cs[math.floor(cs.index(r[-1])/2)]
        if r <= l:
            d = len(l) - len(r)
            if d > 0:
                # l is longer than r
                r = l + (d*cs[0])
                r = r[:-1] + cs[-1]
            else:
                r = l + cs[-1]
        return l, r

    l, r = cs[0], cs[-1]
    ft = '(&{}(cn>={})(cn<={}))'
    results = []
    while 1:
        f = ft.format(simple_filter, l, r)
        conn.search(search_base, f, attributes=attributes)
        if conn.result['result'] == 4:
            # reached max results
            l, r = half(l, r)
        elif r == cs[-1]:
            # done
            results.extend(conn.response)
            break
        else:
            results.extend(conn.response)
            ft = '(&{}(!(cn<={}))(cn<={}))'
            l = r
            r = cs[-1]
    return results

def get_users(conn, search_base):
    ''' get all domain users '''
    return get_all(conn, search_base, '(objectCategory=user)', ['userPrincipalName', 'samAccountName'])

def get_groups(conn, search_base):
    ''' get all domain groups '''
    # use domain as base to get builtin and domain groups in one query
    # alternatively, you can do 2 queries with bases:
    #    cn=users,cn=mydomain,cn=com
    #    cn=users,cn=builtins,cn=mydomain,cn=com
    results = get_all(conn, search_base, '(objectCategory=group)', ['objectSid', 'groupType'])
    return [g for g in results if g.get('dn', None)]

# ms-Mcs-AdmPwd (LAPS password). see also post/windows/gather/credentials/enum_laps
COMPUTER_ATTRIBUTES=['name', 'dNSHostName', 'whenCreated', 'operatingSystem',
                     'operatingSystemServicePack', 'lastLogon', 'logonCount',
                     'operatingSystemHotfix', 'operatingSystemVersion',
                     'location', 'managedBy', 'description', 'ms-Mcs-AdmPwd']

def get_computer(conn, search_base, cn, attributes=[]):
    attributes = list(set(attributes + COMPUTER_ATTRIBUTES))
    conn.search(search_base, '(&(objectCategory=computer)(cn={}))'.format(cn), attributes=attributes)
    return conn.response[0]

def get_computers(conn, search_base, attributes=[]):
    attributes = list(set(attributes + COMPUTER_ATTRIBUTES))
    results = get_all(conn, search_base, '(objectCategory=computer)', attributes)
    return [g for g in results if g.get('dn', None)]

def get_user_dn(conn, search_base, user):
    conn.search(search_base, '(&(objectCategory=user)(|(userPrincipalName={}@*)(cn={})(samAccountName={})))'.format(user, user, user))
    return conn.response[0]['dn']

def get_user_groups(conn, search_base, user):
    ''' get all groups for user, domain and local. see groupType attribute to check domain vs local.
    user should be a dn'''
    conn.search(search_base, '(&(objectCategory=User)(distinguishedName='+user+'))', attributes=['memberOf', 'primaryGroupID'])
    group_dns = conn.response[0]['attributes']['memberOf']

    # get primary group which is not included in the memberOf attribute
    pgid = int(conn.response[0]['attributes']['primaryGroupID'][0])
    groups = get_groups(conn, search_base)
    for g in groups:
        # Builtin group SIDs are returned as str's, not bytes
        if type(g['attributes']['objectSid'][0]) == str:
            g['attributes']['objectSid'][0] = g['attributes']['objectSid'][0].encode()
    gids = [gid_from_sid(g['attributes']['objectSid'][0]) for g in groups]
    group_dns.append(groups[gids.index(pgid)]['dn'])
    group_dns = list(map(str.lower, group_dns))
    return [g for g in groups if g['dn'].lower() in group_dns]

def get_users_in_group(conn, search_base, group):
    ''' return all members of group '''
    groups = get_groups(conn, search_base)
    if group.find('=') > 0:
        group = [g for g in groups if g.get('dn', '').lower() == group.lower()][0] # get group dn
    else:
        group = [g for g in groups if cn(g.get('dn', '')).lower() == group.lower()][0] # get group dn
    gid = gid_from_sid(group['attributes']['objectSid'][0])
    # get all users with primaryGroupID of gid
    conn.search(search_base, '(&(objectCategory=user)(primaryGroupID={}))'.format(gid),
                attributes=['distinguishedName', 'userPrincipalName', 'samAccountName'])
    users = [u for u in conn.response if u.get('dn', False)]
    # get all users in group using "memberOf" attribute. primary group is not included in the "memberOf" attribute
    conn.search(search_base, '(&(objectCategory=user)(memberOf='+group['dn']+'))', attributes=['distinguishedName', 'userPrincipalName'])
    users += [u for u in conn.response if u.get('dn', False)]
    return users

def get_pwd_policy(conn, search_base):
    ''' return non-default password policies for the domain. user must have read access to
    policies in "Password Settings Container" '''
    base = 'cn=Password Settings Container,cn=System,'+search_base
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

def get_user_info(conn, search_base, user):
    user_dn = get_user_dn(conn, search_base, user)
    conn.search(search_base, '(&(objectCategory=user)(distinguishedName={}))'.format(user_dn), attributes=['allowedAttributes'])
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
    conn.search(search_base, '(&(objectCategory=user)(distinguishedName={}))'.format(user_dn), attributes=attrs)
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

def get_default_pwd_policy(args, conn):
    ''' default password policy is what gets returned by "net accounts"
    The policy is stored as a GPO on the sysvol share. It's stored in an INI file.
    The default policy is not returned by get_pwd_policy() '''
    if conn:
        conn.search('cn=Policies,cn=System,'+args.search_base, '(cn={31B2F340-016D-11D2-945F-00C04FB984F9})',
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
                          get_host_by_addr(args.server, args.name_server, args.timeout) or \
                          get_host_by_addr(args.server, args.server, args.timeout) or \
                          get_host_by_addr(args.server, timeout=args.timeout)
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
            args.username, '*', dc_hostname, args.domain))
        conn = SMBConnection(args.username, args.password, 'adenum', dc_hostname, use_ntlm_v2=True,
                             domain=args.domain, is_direct_tcp=(args.smb_port != 139))
        logger.debug('connecting {}:{}'.format(args.server, args.smb_port))
        conn.connect(args.server, port=args.smb_port)
        attrs, size = conn.retrieveFile(sysvol, rel_path, tmp_file)
    else:
        if args.proxy:
            raise RuntimeError('Cannot use smbclient when --proxy is used')
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


def get_dc_info(args, conn=None):
    if not conn:
        server = ldap3.Server(args.server)
        conn = ldap3.Connection(server, auto_bind=True, version=args.version, receive_timeout=args.timeout, timeout=args.timeout)
    conn.search('', '(objectClass=*)', search_scope=ldap3.BASE, dereference_aliases=ldap3.DEREF_NEVER,
                attributes=['dnsHostName', 'supportedLDAPVersion', 'rootDomainNamingContext',
                            'domainFunctionality', 'forestFunctionality', 'domainControllerFunctionality'])
    r = conn.response[0]['raw_attributes']
    for a in r:
        if a == 'supportedLDAPVersion':
            r[a] = list(sorted(map(int, r[a])))
        elif type(r[a][0]) == bytes:
            r[a] = r[a][0].decode()
            if a.endswith('Functionality'):
                r[a] = int(r[a])
        else:
            r[a] = r[a][0]
    r['search_base'] = 'DC='+r['dnsHostName'].split('.', maxsplit=1)[0]+','+r['rootDomainNamingContext']
    return r
