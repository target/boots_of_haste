# Boots of Haste

Boots of Haste is a simple Python program to speed up ingesting Nmap XML data for penetration testing.

## Getting Started

Written and tested with Python 2.7.10. Not tested under Python 3.

### Prerequisites

Boots of Haste uses the Requests library.   

To see if you have Requests installed, use the following command (assuming you use pip):  
```shell
pip show requests
```

To install Requests with pip, use the following command:  
```shell
pip install requests
```

## Running Boots of Haste

usage example:
```
python boots_of_haste.py -i <nmap.xml>

optional arguments:
  -h, --help                      show this help message and exit
  -i INPUT, --input INPUT         the Nmap XML file to parse
  -p PROXY, --proxy PROXY         the IP:Port of proxy to use. Defaults to 127.0.0.1:8080.
  -v, --verbose                   enable verbose output
  -t TIMEOUT, --timeout TIMEOUT   request timeout in seconds, defaults to 2
  --forceDNS                      force script to check for FQDN if only IPs are in the Nmap file
  --checkonly                     enable debug mode. No requests will be sent
```

Boots of Haste will send a GET request to all open ports, even ones that it maybe shouldn't (like FTP or SSH).

By default, Boots of Haste will wait 2 seconds for a response. You can configure this with the ```-t``` or ```--timeout``` flags. If the timeout is reached, you will get an error message and Boots of Haste will move on to the next request. However, it is likely Burp (or your proxy of choice) will still receive the response. In most cases, you can just ignore the timeout errors.

If you are unsure about your Nmap xml file, run with the ```--checkonly``` and ```--verbose``` flags to see what would be sent.

If your Nmap file doesn't have hostnames, just IP addresses, using ```-forceDNS``` will attempt a reverse DNS lookup.

Once you are ready, make sure Burp is running and listening on localhost. If Burp is not listening on port 8080, use ```-p``` or ```--proxy``` to specify your port.


## Contributing

Please see [Contributing](/CONTRIBUTING.md).

## License

This project is licensed under the Apache License v2. Please see [License](/LICENSE) for more details.
