# adenum.py
Remote Active Directory enumeration

## INSTALLATION

You'll need to install ldap3, dnspython, and pysmb:
```
pip3 install ldap3 dnspython pysmb
```

To read the default password policy from the sysvol file share, you'll need either smbclient or pysmb


## Examples
NOTE: when specifying a domain with -d, ensure that your system
is configured to use the DNS server for the domain. Alternatively,
you can specify your domain controller with -s if it's a name server.

### List password policies
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
