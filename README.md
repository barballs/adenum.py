# adenum.py
Remote Active Directory enumeration

## Installation

You'll need to install ldap3, dnspython, and pysmb:
```
pip3 install ldap3 dnspython pysmb
```

To read the default password policy from the SYSVOL share, you'll need either smbclient or pysmb.

## Examples
NOTE: If your system is not configured to use the name server for
the domain, you must specify the domain controller with -s or the
domain's name server with --name-server. In nearly all AD domains,
the domain controller acts as the name server. Domains specified
with -d must be fully qualified.

### List password policies
Non-default policies may require higher privileges.
```
$ python3 adenum.py -u USER -P -d mydomain.local policy
```

### List all users and groups
```
$ python3 adenum.py -u USER -P -d mydomain.local users
$ python3 adenum.py -u USER -P -d mydomain.local groups
```

### List domain admins
```
$ python3 adenum.py -u USER -P -d mydomain.local group "domain admins"
```

### List domain joined computers.
Add -r and -u to resolve hostnames and get uptime (SMB2 only).
```
$ python3 adenum.py -u USER -P -d mydomain.local computers
```

### Resources
all defined AD attributes
```
https://msdn.microsoft.com/en-us/library/ms675090(v=vs.85).aspx
```