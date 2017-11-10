PLUGIN_NAME='gpp'
g_parser = None

def get_parser():
    return g_parser

def handler(args, conn):
    raise NotImplementedError


def get_arg_parser(subparser):
    global g_parser
    if not g_parser:
        g_parser = subparser.add_parser(PLUGIN_NAME, help='Check Group Policy Preferences for creds')
        g_parser.set_defaults(handler=handler)
    return g_parser
