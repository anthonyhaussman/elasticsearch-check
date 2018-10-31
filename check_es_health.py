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
Check healh of an es cluster

exemple :
%s -H es-03 -p 9200 -B 'user:password'

""" % (sys.argv[0])

def read_stats(scheme,host, port, auth, cert, key):
    stats_url = ''.join([scheme, '://', host,':', port, '/_cluster/health'])

    try:
        response = requests.get(stats_url, cert=(cert, key), auth=auth)
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
    parser.add_option("-S", "--ssl", action="store_true", dest="ssl",
                      help="Enable SSL scheme to connect on ES")
    parser.add_option("-B", "--basic-auth",
                      metavar="AUTH",
                      help="Basic auth string 'username:password'",
                      dest="auth",
                      default=None)
    parser.add_option("-c", "--certificate",
                      help="Client certificate path",
                      dest="cert",
                      default=None)
    parser.add_option("-k", "--key",
                      help="Client certificate key path",
                      dest="key",
                      default=None)
    (options,args) = parser.parse_args()

    if not options.host:
        print(usage)
        parser.error("The host option is mandatory. ex : 10.18.71.1")

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

    data = read_stats(scheme,options.host, options.port, options.auth, options.cert, options.key)
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
