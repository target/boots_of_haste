import sys, json, argparse, requests, re, xml.etree.ElementTree, socket
from requests.packages.urllib3.exceptions import InsecureRequestWarning


def sendRequest(requestUrl, requestMethod, requestHeaders):
    """Send the request as passed in."""
    r = ""
    t = float(args.timeout)
    try:
        if requestMethod == "GET":
            r = requests.get(requestUrl, headers=requestHeaders, proxies=p, verify=False, timeout=t)
        elif requestMethod == "HEAD":
            r = requests.head(requestUrl, headers=requestHeaders, proxies=p, verify=False, timeout=t)
        elif requestMethod == "OPTIONS":
            r = requests.options(requestUrl, headers=requestHeaders, proxies=p, verify=False, timeout=t)
        else:
            print "Unsupported Method: " + str(requestMethod)
    except Exception as error:
        if args.verbose:
            print "Error occured on %s - %s" % (requestUrl, type(error))
    return r


def processEndpoints(_endpoints):
    """ Build a URL and send a GET request to it."""
    if(args.verbose):
        print "\nProcessing endpoint information..."
    for _host in _endpoints:
        print "\n[*] Readying requests for host %s" % _host['name']
        print "Found %s ports" % len(_host['ports'])
        for _port in _host['ports']:
            if _port['protocol'] == 'tcp':
                if _port['ssl'] == 'true':
                    _url = "https://"
                else:
                    _url = "http://"
                _url = _url + _host['name'] + ":" +  _port['port']
                if args.verbose:
                    print str(_url)

                if args.checkonly == "false":
                    sendRequest(_url, "GET", headers)
    print "Host complete"

def parseNmapXML():
    print "\nParsing Nmap XML file " + str(args.input)
    _root = xml.etree.ElementTree.parse(args.input).getroot();
    _endpoints = []
    for _host in _root.findall("host"):
        _host_entry = {}
        # check for hostname first
        if _host.find('hostnames').find('hostname') is not None:
            if _host.find('hostnames').find('hostname').attrib['name'] is not None:
                if args.verbose:
                    print "Found host: %s" % _host.find('hostnames').find('hostname').attrib['name']
                _host_entry['name'] = _host.find('hostnames').find('hostname').attrib['name']
        else:
            # if no hostname, use IP address
            if args.verbose:
                print "Found host: %s" % _host.find('address').attrib['addr']

            if args.forceDNS == True:
                try:
                    _host_name = socket.gethostbyaddr(_host.find('address').attrib['addr'])
                    if(args.verbose):
                        print "Reverse DNS: %s" % str(_host_name[0])
                        _host_entry['name'] = _host_name[0]
                except Exception as error:
                    # if an error occurs, just us the IP address
                    print "Error occured during Reverse DNS: %s" % type(error)
                    _host_entry['name'] = _host.find('address').attrib['addr']
            else:
                _host_entry['name'] = _host.find('address').attrib['addr']

        _ports = []

        for _port in _host.find('ports'):
            _port_entry = {}
            if _port.tag == "port":
                if _port.find('state').attrib['state'] == 'open':
                    _port_entry['protocol'] = _port.attrib['protocol']
                    _port_entry['port'] = _port.attrib['portid']
                    # assume SSL is false
                    _port_entry['ssl'] = "false"
                    # but overwrite it if it is set
                    try:
                        if _port.find("service") is not None:
                            if "tunnel" in _port.find("service").attrib:
                                if _port.find("service").attrib["tunnel"] == "ssl":
                                    #print "Found SSL"
                                    _port_entry['ssl'] = "true"
                    except Exception as error:
                        print type(error)
                    _ports.append(_port_entry)

        _host_entry['ports'] = _ports
        _endpoints.append(_host_entry)
    return _endpoints


# Print splash screen
def printSplash():
    print "\n"
    print "            "
    print " __ )              |                _|  |   |            |         "
    print " __ \   _ \   _ \  __|  __|   _ \  |    |   |  _` |  __| __|  _ \  "
    print " |   | (   | (   | |  \__ \  (   | __|  ___ | (   |\__ \ |    __/  "
    print " ____/ \___/ \___/ \__|____/ \___/ _|  _|  _|\__,_|____/\__|\___| "
    print "Version: %s " % version
    print "\n\n"


parser = argparse.ArgumentParser(description="Boots of Haste - automating Burp requests from Nmap XML files")
parser.add_argument("-i", "--input", help="the Nmap XML file to parse", required=True)
parser.add_argument("-p", "--proxy", help="IP:Port of proxy to use. Defaults to localhost:8080.", default="127.0.0.1:8080")
parser.add_argument("-v", "--verbose", help="enable verbose output", action="store_true")
parser.add_argument("-t", "--timeout", help="request timeout in seconds, defaults to 2", default="2")
parser.add_argument("--forceDNS", help="force script to check for FQDN if only IPs are in the Nmap file", action="store_true", default="false")
parser.add_argument("--checkonly", help="enable debug mode. No requests will be sent", action="store_true", default="false")
args = parser.parse_args()


version = "1.0.2"
headers = dict()
headers["User-Agent"] = "boots_of_haste"

requests.packages.urllib3.disable_warnings(InsecureRequestWarning) # disable this since we're sending requests through Burp/local proxy
p = {"http": "http://" + args.proxy, "https": "https://" + args.proxy}


printSplash()

if(args.verbose):
    print str(args)

endpoints = parseNmapXML()

processEndpoints(endpoints)
