#!/usr/bin/env python2
"""
Author : Anthony Hausman
License stuff

Count the number of documents created in a specific ElasticSearch index
"""
import sys
import urllib2
import json
import base64
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

def read_stats(host, port, node, auth):
    stats_url = ''.join(['http://', host,':', port, '/_nodes/', node,'/stats'])
     
    try:
        req = urllib2.Request(stats_url)
        if auth:
            base64str = base64.encodestring(auth).replace('\n', '')
            req.add_header('Authorization', 'Basic %s' % base64str)
        response = urllib2.urlopen(req, timeout=5)
    except urllib2.URLError, e:
        print("UNKNOWN : %s" % e)
        sys.exit(UNKNOWN)
    else:
        data = response.read()
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

    data = read_stats(options.host, options.port, options.node, options.auth)
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
