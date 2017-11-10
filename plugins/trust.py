PLUGIN_NAME='trust'
g_parser = None

def get_parser():
    return g_parser

def handler(args, conn):
    attributes=['SourceName', 'SourceSID', 'TargeName', 'TargetSID', 'TrustType', 'TrustDirection']
    conn.search(args.search_base, '(objectClass=trustedDomain)', attributes=attributes)
    for r in conn.response:
        print(r)


def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='list all domain trusts')
        g_parser.set_defaults(handler=handler)
    return g_parser
