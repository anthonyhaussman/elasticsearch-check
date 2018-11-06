#!/usr/bin/env python2
"""
Author : Anthony Hausman
License stuff

Count the number of documents created in a specific ElasticSearch index
"""
import sys
import json
import requests
import os
import errno
import json
import datetime
from requests.auth import HTTPBasicAuth
from datetime import date, timedelta
from optparse import OptionParser

# Exit statuses recognized by Shinken
OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3

usage = """
Check document creation increasement in a specific index

exemple :
%s -H es-03 -p 9200 -B 'user:password' -I logstash -W 100 -C 0

""" % (sys.argv[0])

def read_stats(scheme, host, port, index, auth, date, cert, key, ca):
    stats_url = ''.join([scheme, '://', host,':', port, '/_cat/count/', index, '-', date ,'?format=json'])

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

def silentremove(filename):
    try:
        os.remove(filename)
    except OSError as e: # this would be "except OSError, e:" before Python 2.6
        if e.errno != errno.ENOENT: # errno.ENOENT = no such file or directory
            raise # re-raise exception if a different error occurred

if __name__ == '__main__':

    parser = OptionParser(version="1.0")
    parser.add_option("-H", "--host", dest="host",
                      help="ip address/hostname of the webserver")
    parser.add_option("-p", "--port", dest="port", default="80",
                      help="tcp port of the webserver")
    parser.add_option("-I", "--index",dest="index", default='logstash',
                      help="Path to http counters page")
    parser.add_option("-B", "--basic-auth",
                      metavar="AUTH",
                      help="Basic auth string 'username:password'",
                      dest="auth",
                      default=None)
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
    elif not options.warn:
        print(usage)
        parser.error("The warning threshold must be set")
    elif not options.crit:
        print(usage)
        parser.error("The critical threshold must be set")

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

    today = datetime.date.today()
    date = today.strftime('%Y.%m.%d')

    data = read_stats(scheme, options.host, options.port, options.index, options.auth, date, options.cert, options.key, options.ca)
    stats = json.loads(data)

    count = stats[0]['count']

    date_file = '/tmp/.date-%s-%s-%s' % ( os.path.basename(sys.argv[0]).rsplit(".",1)[0],options.host, options.index)
    old_statsfile = '/tmp/.%s-%s-%s' % ( os.path.basename(sys.argv[0]).rsplit(".",1)[0],options.host, options.index)

    if os.path.isfile(date_file):
        with open(date_file, 'r') as f:
            previous_date = f.read()
        f.closed
    else:
        previous_date = 0

    if str(previous_date) != str(today):
        with open(date_file, 'w') as f:
            f.write(str(today))
        f.closed
        silentremove(old_statsfile)

    if os.path.isfile(old_statsfile):
        with open(old_statsfile, 'r') as f:
            old_stats = json.loads(f.read())
        f.closed
        previous_count = old_stats[0]['count']
        count = int(count) - int(previous_count)

    with open(old_statsfile, 'w') as f:
        f.write(str(data))
    f.closed

    # Exit code
    if count <= int(options.warn) and count > int(options.crit):
        print("WARNING : Number of documents for index %s created : %s" % (options.index, count))
        sys.exit(WARNING)
    elif count <= int(options.crit):
        print("CRITICAL : Number of documents for index %s created : %s" % (options.index, count))
        sys.exit(CRITICAL)
    else:
        print("OK : Number of documents for index %s created : %s" % (options.index, count))
        sys.exit(OK)
