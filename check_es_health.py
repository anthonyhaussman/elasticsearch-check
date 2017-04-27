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
Check healh of an es cluster

exemple :
%s -H es-03.gcp.dailymotion.com -p 9200 -B 'user:password'

""" % (sys.argv[0])

def read_stats(host, port, auth):
    stats_url = ''.join(['http://', host,':', port, '/_cluster/health'])
     
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
    (options,args) = parser.parse_args()

    if not options.host:
        print(usage)
        parser.error("The host option is mandatory. ex : 10.18.71.1")

    data = read_stats(options.host, options.port, options.auth)
    stats = json.loads(data)

    status = stats['status']

    # Exit code
    if status == str('yellow'):
        print("WARNING : The ES cluster is in %s status" % (status))
        sys.exit(WARNING)
    elif status == str('red'):
        print("CRITICAL : The ES cluster is in %s status" % (status))
        sys.exit(CRITICAL)
    else:
        print("OK : The ES cluster is in %s status" % (status))
        sys.exit(OK)
