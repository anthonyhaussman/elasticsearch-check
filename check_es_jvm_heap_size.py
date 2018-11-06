#!/usr/bin/env python2
"""
Author : Anthony Hausman
License stuff

Count the number of documents created in a specific ElasticSearch index
"""
import sys
import json
import requests
from requests.auth import HTTPBasicAuth
from optparse import OptionParser

# Exit statuses recognized by Shinken
OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3

usage = """
Check heap memory percent use on a node

exemple :
%s -H es-02 -p 9200 -N es-02 -B 'user:password' -W 80 -C 90

""" % (sys.argv[0])

def read_stats(scheme, host, port, node, auth, cert, key, ca):
    stats_url = ''.join([scheme, '://', host,':', port, '/_nodes/', node,'/stats'])

    try:
        response = requests.get(stats_url, cert=(cert, key), verify=ca, auth=auth)
        if not response.status_code // 100 == 2:
            print "Error: Unexpected response {}".format(response)
            sys.exit(CRITICAL)
    except requests.exceptions.HTTPError as err:
        print err
        sys.exit(CRITICAL)
    except requests.exceptions.RequestException as e:  # This is the correct syntax
        print e
        sys.exit(CRITICAL)
    else:
        data = response.content
    response.close
    return(data)

if __name__ == '__main__':

    parser = OptionParser(version="1.0")
    parser.add_option("-H", "--host", dest="host",
                      help="ip address/hostname of the webserver")
    parser.add_option("-p", "--port", dest="port", default="80",
                      help="tcp port of the webserver")
    parser.add_option("-B", "--basic-auth",
                      metavar="AUTH",
                      help="Basic auth string 'username:password'",
                      dest="auth",
                      default=None)
    parser.add_option("-N", "--node", dest="node",
                      help="Name of the node to check")
    parser.add_option("-W", "--warning", dest="warn", help="Warning Threshold")
    parser.add_option("-C", "--critical", dest="crit", help="Critical Threshold")
    parser.add_option("-S", "--ssl", action="store_true", dest="ssl",
                      help="Enable SSL scheme to connect on ES")
    parser.add_option("-c", "--certificate",
                      help="Client certificate path",
                      dest="cert",
                      default=None)
    parser.add_option("-k", "--key",
                      help="Client certificate key path",
                      dest="key",
                      default=None)
    parser.add_option("-a", "--certificate-authority",
                      help="Certificate Authority path",
                      dest="ca",
                      default=None)
    (options,args) = parser.parse_args()

    if not options.host:
        print(usage)
        parser.error("The host option is mandatory. ex : 10.18.71.1")
    elif not options.node:
        print(usage)
        parser.error("The node option is mandatory. ex : es-01")
    elif not options.warn:
        print(usage)
        parser.error("The warning threshold must be set")
    elif not options.crit:
        print(usage)
        parser.error("The critical threshold must be set")
    elif options.warn > options.crit:
        print(usage)
        parser.error("The warning value must be lower than critical")

    if options.ssl:
       scheme="https"
    else:
       scheme="http"

    if options.cert and not options.ssl:
        print "CRITICAL : Need to specify the SSL option (-S or --ssl)"
        sys.exit(CRITICAL)
    elif options.cert and not options.key:
        print "CRITICAL : Need to specify the key file (-k or --key)"
        sys.exit(CRITICAL)

    if options.key and not options.ssl:
        print "CRITICAL : Need to specify the SSL option (-S or --ssl)"
        sys.exit(CRITICAL)
    elif options.key and not options.cert:
        print "CRITICAL : Need to specify the certificate file (-c or --cert)"
        sys.exit(CRITICAL)

    if options.auth:
       login=options.auth.split(":", 1)[0]
       password=options.auth.split(":", 1)[1]
       options.auth = HTTPBasicAuth(login, password)


    data = read_stats(scheme, options.host, options.port, options.node, options.auth, options.cert, options.key, options.ca)
    stats = json.loads(data)

    heap_percent = stats['nodes'].values()[0]['jvm']['mem']['heap_used_percent']

    # Exit code
    if heap_percent >= int(options.warn) and heap_percent < int(options.crit):
        print('WARNING : Heap memory on {} = {}%'.format(options.node, heap_percent))
        sys.exit(WARNING)
    elif heap_percent >= int(options.crit):
        print('CRITICAL : Heap memory on {} = {}%'.format(options.node, heap_percent))
        sys.exit(CRITICAL)
    else:
        print('OK : Heap memory on {} = {}%'.format(options.node, heap_percent))
        sys.exit(OK)
